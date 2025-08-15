const ethers = require('ethers');
const fs = require('fs');

// const BigNumber = require("bignumber.js");
const abi = JSON.parse(fs.readFileSync("./abis/abi"));
const provider = new ethers.getDefaultProvider('https://testnet-rpc.cess.cloud/ws/');
const privateKey = "82b46d10cd14ec7afe513bcb1f2283125255798dda67e0c35293954dffe206d3"; // wo // ni
const wallet = new ethers.Wallet(privateKey, provider);
const ContractAddr = '0x636b7E4E9b7331047b431179809F3546e1f7A841';
const contract = new ethers.Contract(ContractAddr, abi, provider);
const contractWithSigner = contract.connect(wallet);

module.exports = {
    mintToken: async (req, res) => {
        let overrides = {
            value: "100000000000000000000",
        };
        let tx = await contractWithSigner.mintToken("0xFd0Cc11A9ffbA29F7db7734b6dc39b1e5212Bb1c", overrides);
        console.log(tx.hash);

        await tx.wait();

        console.log("aquoteSend:" + JSON.stringify(tx) + "\n");

        contract.on("MintToken", (owner, tokenId) => {
            console.log(owner);
            console.log(tokenId);
        });

        res.json({
            "msg": "ok"
        });
    }
}



