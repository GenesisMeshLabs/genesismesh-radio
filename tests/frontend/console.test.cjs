const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');

function harness() {
  const nodes = new Map();
  function node(id) {
    if(!nodes.has(id)) nodes.set(id, {textContent:'',disabled:false,hidden:false,value:'',
      addEventListener(name,callback){this[name]=callback;},replaceChildren(){},append(){}});
    return nodes.get(id);
  }
  let resolveFetch;
  const context = vm.createContext({
    document:{getElementById:node,addEventListener(){},hidden:false},
    localStorage:{getItem(){return null;},setItem(){},removeItem(){}},
    setInterval(){}, fetch(){return new Promise(resolve=>{resolveFetch=resolve;});},
    crypto:{randomUUID(){return '22222222-2222-4222-8222-222222222222';}},
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname,
    '../../src/genesismesh_radio/console/assets/app.js'),'utf8'),context);
  return {context,node,respond(data,ok=true){resolveFetch({ok,status:ok?200:503,json:async()=>data});}};
}
const A='11111111-1111-4111-8111-111111111111';
const B='22222222-2222-4222-8222-222222222222';

test('late lookup for A cannot label newer B confirmed or release its request ID', async()=>{
  const h=harness();
  vm.runInContext(`intent={command_id:'${A}'};`,h.context);
  const pending=vm.runInContext('lookup()',h.context);
  vm.runInContext(`intent={command_id:'${B}'};clearResult();`,h.context);
  h.respond({command:{command_id:A,state:'confirmed',report_status:'accepted'}});
  await pending;
  assert.equal(h.node('request-id').textContent,B);
  assert.equal(h.node('outcome').textContent,'Unconfirmed');
  assert.equal(h.node('new-request').disabled,true);
});

test('late error for A leaves newer B outcome untouched', async()=>{
  const h=harness();
  vm.runInContext(`intent={command_id:'${A}'};`,h.context);
  const pending=vm.runInContext('lookup()',h.context);
  vm.runInContext(`intent={command_id:'${B}'};clearResult();`,h.context);
  h.respond({code:'old_request_unavailable'},false);
  await pending;
  assert.equal(h.node('request-id').textContent,B);
  assert.equal(h.node('request-detail').textContent,'Awaiting the result for this request ID.');
});

test('mismatched backend command ID cannot become completion', ()=>{
  const h=harness();
  vm.runInContext(`intent={command_id:'${B}'};clearResult();result({command_id:'${A}',state:'confirmed'},'${B}');`,h.context);
  assert.equal(h.node('outcome').textContent,'Unconfirmed');
  assert.equal(h.node('new-request').disabled,true);
});

test('matching terminal result enables a deliberate new request and clears old evidence', ()=>{
  const h=harness();
  vm.runInContext(`identity={role:'operator'};intent={command_id:'${A}'};result({command_id:'${A}',state:'confirmed',report_status:'accepted'},'${A}');`,h.context);
  assert.equal(h.node('new-request').disabled,false);
  h.node('new-request').click();
  assert.equal(h.node('request-id').textContent,'No request yet');
  assert.equal(h.node('outcome').textContent,'—');
  assert.equal(h.node('report').textContent,'—');
  assert.equal(h.node('new-request').disabled,true);
});

test('authorization expiry before dispatch permits a deliberate new request', ()=>{
  const h=harness();
  vm.runInContext(`intent={command_id:'${A}'};result({command_id:'${A}',state:'expired',report_status:'accepted'},'${A}');`,h.context);
  assert.equal(h.node('new-request').disabled,false);
  assert.equal(h.node('outcome').textContent,'expired');
});
