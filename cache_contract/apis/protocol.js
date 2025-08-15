const ethers = require('ethers');
const fs = require('fs');
// const Tx = require("ethereumjs-tx");
// const BigNumber = require("bignumber.js");
const abi = JSON.parse(fs.readFileSync("./abis/pabi"));
const provider = new ethers.getDefaultProvider('https://testnet-rpc.cess.cloud/ws/');
const privateKey = "82b46d10cd14ec7afe513bcb1f2283125255798dda67e0c35293954dffe206d3";
const wallet = new ethers.Wallet(privateKey, provider);
const ContractAddr = '0x7352188979857675C3aD1AA6662326ebD6DDBf6d';
const contract = new ethers.Contract(ContractAddr, abi, provider);
const contractWithSigner = contract.connect(wallet);

module.exports = {
    isTokenOwner: async (req, res) => {
        let tx = await contractWithSigner.isTokenOwner("0xFd0Cc11A9ffbA29F7db7734b6dc39b1e5212Bb1c", "89299461066820231595682757968756880840560145332110387682901734191710853064278");
        console.log(tx.hash);
        // "0xaf0068dcf728afa5accd02172867627da4e6f946dfb8174a7be31f01b11d5364"

        console.log("isTokenOwner:" + JSON.stringify(tx) + "\n");

        res.json({
            "msg": "ok"
        });
    }

    
}