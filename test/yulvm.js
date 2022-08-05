const YulVM = artifacts.require("YulVM");
const SolVM = artifacts.require("SolVM");
/*
 * uncomment accounts to access the test accounts made available by the
 * Ethereum client
 * See docs: https://www.trufflesuite.com/docs/truffle/testing/writing-tests-in-javascript
 */

async function shouldSucceed(instance,bytecode) {
  const result = await instance.executeBytecode(web3.eth.abi.encodeParameter('bytes', bytecode));
  console.log(result);
  assert.isTrue(result.receipt.status);
}
async function shouldRevert(instance,bytecode) {
  const result = await instance.executeBytecode(web3.eth.abi.encodeParameter('bytes', bytecode));
  console.log(result)
  assert.isTrue(!result.receipt.status);
}
contract("YulVM", function (/* accounts */) {
  it("should assert true", async function () {
    const instance = await YulVM.deployed();
    return assert.isTrue(true);
  });
  it("should do nothing and STOP with no calldata", async function() {
    const deployed = await YulVM.deployed();
    // lil hack to get around the lack of ABI on YulVM
    const instance = await SolVM.at(deployed.address);
    await shouldRevert(instance,'0x');
    //const bytecode = web3.eth.abi.encodeFunctionCall(abi[0], ['0x']);
  });
  it("should revert with STOP opcode", async function() {
    const deployed = await YulVM.deployed();
    // lil hack to get around the lack of ABI on YulVM
    const instance = await SolVM.at(deployed.address);
    await shouldRevert(instance,'0x00');
  });
  it("should return success with a RETURN(0,0)", async function() {
    const deployed = await YulVM.deployed();
    // lil hack to get around the lack of ABI on YulVM
    const instance = await SolVM.at(deployed.address);
    await shouldSucceed(instance,'0x700080f3');
  });

});
