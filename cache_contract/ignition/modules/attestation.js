const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");

// npx hardhat ignore
// npx hardhat ignition deploy ./ignition/modules/attestation.js --network cessdev
module.exports = buildModule("attestation", (m) => {
  const contract = m.contract("attestation", ["0x16b7E23E35f3f8A6FAE1B8f6C8d4024A21Bf2f44"]);

  return { contract };
});