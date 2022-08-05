const YulVM = artifacts.require("YulVM");

module.exports = function (deployer) {
  deployer.deploy(YulVM);
};
