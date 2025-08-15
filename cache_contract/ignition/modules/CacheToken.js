const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");

module.exports = buildModule("CacheToken", (m) => {
  const contract = m.contract("CacheToken", ["YTQALJN", "YSG"]);

  return { contract };
});
