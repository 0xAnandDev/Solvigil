const parser = require('@solidity-parser/parser');

function containsMsgSender(node) {
  let found = false;
  if (!node) return found;
  parser.visit(node, {
    MemberAccess(maNode) {
      if (maNode.expression && maNode.expression.type === 'Identifier' && maNode.expression.name === 'msg' && maNode.memberName === 'sender') {
        found = true;
      }
    }
  });
  return found;
}

function analyzeCritical(funcNode) {
  let isCritical = false;
  const localVars = new Set();
  
  if (funcNode.parameters) {
    for (const p of funcNode.parameters) {
      if (p.name) localVars.add(p.name);
    }
  }
  
  if (!funcNode.body) return false;
  
  parser.visit(funcNode.body, {
    VariableDeclaration(varNode) {
      if (varNode.name) localVars.add(varNode.name);
    }
  });

  parser.visit(funcNode.body, {
    BinaryOperation(binNode) {
      if (['=', '+=', '-=', '*=', '/='].includes(binNode.operator)) {
        if (binNode.left.type === 'Identifier') {
          if (!localVars.has(binNode.left.name)) {
            console.log('Critical: Modifies state var', binNode.left.name);
            isCritical = true;
          }
        } else if (binNode.left.type === 'MemberAccess') {
          if (binNode.left.expression && binNode.left.expression.type === 'Identifier') {
             if (!localVars.has(binNode.left.expression.name)) {
                 console.log('Critical: Modifies state struct/member', binNode.left.expression.name);
                 isCritical = true;
             }
          } else {
             if (!containsMsgSender(binNode.left)) {
                 console.log('Critical: Modifies complex member not tied to msg.sender');
                 isCritical = true;
             }
          }
        } else if (binNode.left.type === 'IndexAccess') {
          if (!containsMsgSender(binNode.left.index)) {
             let baseName = '';
             if (binNode.left.base && binNode.left.base.type === 'Identifier') {
                 baseName = binNode.left.base.name;
             }
             if (baseName && !localVars.has(baseName)) {
                 console.log('Critical: Modifies global mapping or other user data', baseName);
                 isCritical = true;
             } else if (!baseName) {
                 console.log('Critical: Modifies complex global mapping');
                 isCritical = true;
             }
          }
        }
      }
    },
    FunctionCall(callNode) {
      if (callNode.expression && callNode.expression.type === 'MemberAccess') {
        const memberName = callNode.expression.memberName;
        if (['transfer', 'send', 'call'].includes(memberName)) {
           if (!containsMsgSender(callNode.expression.expression)) {
              console.log('Critical: Transfers to non-msg.sender');
              isCritical = true;
           } else {
              for (const arg of callNode.arguments) {
                 let usesContractBalance = false;
                 parser.visit(arg, {
                   MemberAccess(maNode) {
                     if (maNode.memberName === 'balance') usesContractBalance = true;
                   }
                 });
                 if (usesContractBalance) {
                    console.log('Critical: Transfers contract balance');
                    isCritical = true;
                 }
              }
           }
        }
      }
      if (callNode.expression && callNode.expression.type === 'Identifier' && callNode.expression.name === 'selfdestruct') {
         console.log('Critical: selfdestruct');
         isCritical = true;
      }
    }
  });
  return isCritical;
}

const source = `
contract Test {
    uint public owner;
    mapping(address => uint) public balances;
    struct Config { bool paused; }
    Config public config;

    function setOwner(uint _owner) public { owner = _owner; } // Critical
    function withdrawAll() public { msg.sender.transfer(address(this).balance); } // Critical
    function withdrawUser() public { msg.sender.transfer(balances[msg.sender]); balances[msg.sender] = 0; } // NOT critical
    function pause() public { config.paused = true; } // Critical
    function modifyOther(address to) public { balances[to] = 50; } // Critical
    function safeTransfer(address to, uint amt) public { require(msg.sender == owner); balances[to] += amt; balances[msg.sender] -= amt; } // Critical (but will be saved by require)
}
`;

const ast = parser.parse(source, { loc: true });
parser.visit(ast, {
  FunctionDefinition(funcNode) {
    if (funcNode.name) {
      console.log('---', funcNode.name, '---');
      const isCrit = analyzeCritical(funcNode);
      console.log('Is Critical:', isCrit);
    }
  }
});
