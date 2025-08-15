package client

import (
	"os"

	"github.com/ipfs/boxo/blockservice"
	blockstore "github.com/ipfs/boxo/blockstore"
	chunker "github.com/ipfs/boxo/chunker"
	offline "github.com/ipfs/boxo/exchange/offline"
	"github.com/ipfs/boxo/ipld/merkledag"
	"github.com/ipfs/go-cid"
	"github.com/ipfs/go-datastore"
	dsync "github.com/ipfs/go-datastore/sync"
	"github.com/ipfs/go-unixfs/importer/balanced"
	uih "github.com/ipfs/go-unixfs/importer/helpers"
	"github.com/multiformats/go-multicodec"
	"github.com/pkg/errors"
)

const (
	CID_V0 = "v0"
	CID_V1 = "v1"
)

func ComputeCid(fpath, version string) (string, error) {
	var builder cid.Builder
	switch version {
	case CID_V0:
		builder = cid.V0Builder{}
	case CID_V1:
		builder = cid.V1Builder{
			Codec:    uint64(multicodec.Raw),
			MhType:   uint64(multicodec.Sha2_256), //SHA2-256
			MhLength: -1,
		}
	default:
		builder = cid.V0Builder{}
	}

	bs := blockstore.NewIdStore(blockstore.NewBlockstore(dsync.MutexWrap(datastore.NewNullDatastore())))
	bsrv := blockservice.New(bs, offline.Exchange(bs))
	dsrv := merkledag.NewDAGService(bsrv)
	ufsImportParams := uih.DagBuilderParams{
		Maxlinks:   uih.DefaultLinksPerBlock,
		RawLeaves:  false,
		CidBuilder: builder,
		Dagserv:    dsrv,
		NoCopy:     false,
	}
	file, err := os.Open(fpath)
	if err != nil {
		return "", errors.Wrap(err, "compute data cid error")
	}
	defer file.Close()
	ufsBuilder, err := ufsImportParams.New(chunker.NewSizeSplitter(file, chunker.DefaultBlockSize))
	if err != nil {
		return "", errors.Wrap(err, "compute data cid error")
	}

	nd, err := balanced.Layout(ufsBuilder)
	if err != nil {
		return "", errors.Wrap(err, "compute data cid error")
	}
	return nd.Cid().String(), nil
}
