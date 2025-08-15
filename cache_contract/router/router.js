const express = require('express');
const app = new express();
const call = require('../apis/api');
const pcall = require('../apis/protocol');
const router = express.Router();
const bodyParser = require('body-parser');
app.use(bodyParser.urlencoded({extend: false}));
app.use(bodyParser.json());
app.use(router);
// router.get('/name', call.name);
// router.get('/balanceOf', call.balanceOf);
router.get('/mintToken', call.mintToken);

router.get('/isTokenOwner', pcall.isTokenOwner)

app.listen(7070, '127.0.0.1', () => console.log("正在监听端口"));