_: compile

compile:
	truffle compile
.PHONY: compile

YulVM.yul.out: contracts/YulVM.yul
	solc --strict-assembly contracts/YulVM.yul > YulVM.yul.out

