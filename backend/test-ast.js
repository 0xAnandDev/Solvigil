const parser = require('@solidity-parser/parser');

const source = `
contract Test {
    uint public owner;
    mapping(address => uint) public balances;

    function setOwner(uint _owner) public {
        owner = _owner;
    }

    function withdraw() public {
        msg.sender.transfer(address(this).balance);
    }

    function withdrawUser() public {
        msg.sender.transfer(balances[msg.sender]);
        balances[msg.sender] = 0;
    }
}
`;

const ast = parser.parse(source, { loc: true });
console.log(JSON.stringify(ast, null, 2));
