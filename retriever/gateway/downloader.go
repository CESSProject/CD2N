package gateway

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/CD2N/CD2N/retriever/config"
	"github.com/CD2N/CD2N/retriever/node"
	"github.com/CD2N/CD2N/sdk/sdkgo/chain"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/buffer"
	"github.com/CD2N/CD2N/sdk/sdkgo/logger"
	"github.com/pkg/errors"
)

type DataInfo struct {
	Fid, Name, Path, Target string
	Start, End              int64
	DecryptedFilePath       string
}

type Segment struct {
	Index int
	Path  string
}

func (g *Gateway) RetrieveDataFromCache(fid, key, segment, dataRange string) (DataInfo, error) {
	var (
		info DataInfo = DataInfo{Fid: fid, Target: segment}
		err  error
	)
	item := g.FileCacher.GetData(key)
	if item.Value == "" {
		return info, errors.Wrap(errors.New("data not found"), "download data error")
	}
	fname, fpath := buffer.SplitNamePath(item.Value)
	if fname == "" || fname == buffer.UNNAMED_FILENAME {
		if fname, err = g.GetFileName(fid); err != nil {
			logger.GetLogger(config.LOG_GATEWAY).Infof("get file %s name error %v", key, err)
			fname = key
		}
	}
	info.Name = fname
	info.Path = fpath
	if dataRange != "" {
		info.Start, info.End, err = ParseFileRange(dataRange)
		if err != nil {
			return info, errors.Wrap(err, "download data error")
		}
	}
	return info, nil
}

func (g *Gateway) GetFileName(fid string) (string, error) {
	var fname string
	cli, err := g.GetCessClient()
	if err != nil {
		return fname, errors.Wrap(err, "get file name error")
	}
	meta, err := cli.QueryFileMetadata(fid, 0)
	if err == nil {
		for _, owner := range meta.Owner {
			fname = string(owner.FileName)
			if fname != "" {
				return fname, nil
			}
		}
	}
	dealmap, err := cli.QueryDealMap(fid, 0)
	if err != nil {
		return fname, errors.Wrap(err, "get file name error")
	}
	fname = string(dealmap.User.FileName)
	return fname, nil
}

func (g *Gateway) DownloadData(ctx context.Context, b *buffer.FileBuffer, rr *node.ResourceRetriever, fid, segment, dataRange string) (DataInfo, error) {
	var (
		info DataInfo = DataInfo{Fid: fid, Name: "Unknow"}
		err  error
	)
	cessCli, err := g.GetCessClient()
	if err != nil {
		return info, errors.Wrap(err, "download data error")
	}
	fmeta, err := cessCli.QueryFileMetadata(fid, 0)
	if err != nil {
		return info, errors.Wrap(err, "download data error")
	}

	if len(fmeta.Owner) > 0 {
		info.Name = string(fmeta.Owner[0].FileName)
	}

	if dataRange != "" {
		info.Start, info.End, err = ParseFileRange(dataRange)
		if err != nil {
			return info, errors.Wrap(err, "download data error")
		}
	}

	if segment == "" && dataRange != "" {
		segment, info.Start, info.End = GetSegmentByRange(fmeta, info.Start, info.End)
	}
	info.Target = segment

	if err := g.downloadFromCess(ctx, b, rr, &info, fmeta); err != nil {
		return info, errors.Wrap(err, "download data error")
	}

	return info, nil
}

func (g *Gateway) downloadFromCess(ctx context.Context, b *buffer.FileBuffer, rr *node.ResourceRetriever, info *DataInfo, meta chain.FileMetadata) error {
	once, wg := &sync.Once{}, &sync.WaitGroup{}
	segpathCh, errCh := make(chan Segment, len(meta.SegmentList)), make(chan error, 1)
	cli, err := g.GetCessClient()
	if err != nil {
		return errors.Wrap(err, "download data error")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer once.Do(cancel)

	for i, seg := range meta.SegmentList {
		sid := string(seg.Hash[:])
		if info.Target != "" && sid != info.Target {
			continue
		}

		item := g.FileCacher.GetData(string(seg.Hash[:]))
		if item.Value != "" {
			segpathCh <- Segment{Index: i, Path: item.Value}
			continue
		}
		fragments, fragPaths := ParseDataIds(seg), []string{}
		sinfo := Segment{Index: i}
		wg.Add(1)
		if err := g.dlPool.Submit(func() {
			defer wg.Done()
			fragPaths, fragments = GetDataFromDiskBuffer(b, fragments...) //retrieve from local buffer
			logger.GetLogger(config.LOG_GATEWAY).Infof("get fragments from local disk buffer:%v", len(fragPaths))

			if len(fragPaths) < config.FRAGMENTS_NUM { //retrieve from L2 node, triggered when cache miss, low efficiency
				ctx, cancel := context.WithTimeout(ctx, time.Second*15)
				defer cancel()
				task := node.NewCesRetrieveTask(cli, "", info.Fid, sid, fragments)
				paths, err := rr.RetrieveData(ctx, task)
				if err != nil {
					once.Do(func() {
						errCh <- err
						cancel()
					})
					return
				}
				fragPaths = append(fragPaths, paths...)
				logger.GetLogger(config.LOG_GATEWAY).Infof("get fragments from miner pool(bridged via L2 cachers):%v", len(paths))
			}
			//deal with fragments
			if len(fragPaths) < config.FRAGMENTS_NUM {
				once.Do(func() {
					errCh <- errors.New("insufficient cached fragments")
					cancel()
				})
				return
			}

			segPath, err := g.CompositeSegment(sid, fragPaths)
			if err != nil {
				once.Do(func() {
					errCh <- err
					cancel()
				})
				return
			}
			g.BatchOffloadingWithPaths(fragPaths)
			sinfo.Path = segPath
			segpathCh <- sinfo
		}); err != nil {
			return errors.Wrap(err, "download data error")
		}
	}

	wg.Wait()

	if info.Target != "" && len(segpathCh) != 1 || info.Target == "" &&
		(len(segpathCh) != len(meta.SegmentList) || len(segpathCh) <= 0) {
		return errors.Wrap(err, "download data error")
	}
	close(segpathCh)
	segPaths := make([]string, len(segpathCh))
	for info := range segpathCh {
		segPaths[info.Index] = info.Path
	}
	fpath, err := g.CombineFileIntoCache(info.Fid, meta.FileSize.Int64(), segPaths)
	if err != nil {
		return errors.Wrap(err, "download data error")
	}
	info.Path = fpath
	return nil
}

func GetDataFromDiskBuffer(b *buffer.FileBuffer, dids ...string) ([]string, []string) {
	var (
		res  []string
		rems []string
	)
	for _, did := range dids {
		item := b.GetData(did)
		if item.Value != "" {
			res = append(res, item.Value)
		} else {
			rems = append(rems, did)
		}
		if len(res) >= config.FRAGMENTS_NUM {
			return res, rems
		}
	}
	return res, rems
}

func GetSegmentByRange(meta chain.FileMetadata, start, end int64) (string, int64, int64) {
	if end-start <= 0 || end-start > PLAINTEXT_BLOCK_SIZE ||
		start%config.FRAGMENT_SIZE+(end-start) > PLAINTEXT_BLOCK_SIZE ||
		end < meta.FileSize.Int64() {
		return "", start, end
	}
	index := start / config.FRAGMENT_SIZE
	if index >= int64(len(meta.SegmentList)) {
		return "", start, end
	}
	if index > 0 {
		start -= index * config.FRAGMENT_SIZE
		end -= index * config.FRAGMENT_SIZE
	}
	return string(meta.SegmentList[index].Hash[:]), start, end
}

func ParseFileRange(frange string) (int64, int64, error) {
	ranges := strings.Split(frange, "=")
	if len(ranges) != 2 || ranges[0] != "bytes" {
		return 0, 0, errors.Wrap(errors.New("invalid range"), "parse file range error")
	}
	parts := strings.Split(ranges[1], "-")
	if len(parts) != 2 {
		return 0, 0, errors.Wrap(errors.New("invalid range"), "parse file range error")
	}
	start, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, 0, errors.Wrap(err, "parse file range error")
	}
	var end int64
	if parts[1] != "" {
		end, err = strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return 0, 0, errors.Wrap(err, "parse file range error")
		}
	}
	return start, end, nil
}

func ParseDataIds(segment chain.SegmentInfo) []string {
	dids := make([]string, 0, len(segment.FragmentList))
	for _, fragment := range segment.FragmentList {
		dids = append(dids, string(fragment.Hash[:]))
	}
	return dids
}
