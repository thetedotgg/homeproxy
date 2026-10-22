import assert from "node:assert/strict";
import test from "node:test";
import {preparationInput,escapePreparationText,preparationReason,updatePreparationJobs} from "../target/ui-tests/offline-preparation.js";

test("preparation accepts bounded public URLs without changing query order",()=>{
  const raw="https://cdn.example/a?b=2&a=1\nhttp://example.org:8080/file";
  assert.deepEqual(preparationInput(raw,"64",true),{urls:raw.split("\n"),budgetMib:64,pin:true});
});
test("preparation rejects credentials, fragments, non-HTTP schemes and invalid budgets",()=>{
  for(const raw of ["https://user:secret@example.org/a","file:///etc/passwd","https://example.org/a#b","https://example.org:8443/a","", "https://example.org/a\nhttps://example.org/a",Array.from({length:33},(_,i)=>`https://example.org/${i}`).join("\n")]) assert.equal(preparationInput(raw,"64",true),null);
  for(const budget of ["0","1025","1.5","1e2","-1",""]) assert.equal(preparationInput("https://example.org/a",budget,true),null);
});
test("origin labels are escaped and failures have localized messages",()=>{
  assert.equal(escapePreparationText('<script a="x">&'),"&lt;script a=&quot;x&quot;&gt;&amp;");
  assert.match(preparationReason("https-not-inspected","cs"),/HTTPS/);
  assert.match(preparationReason("manifest-write-failed","en"),/stopped/);
  assert.notEqual(preparationReason("unknown","cs"),"unknown");
});

test("manual disclosure choices survive repeated polls, progress and a new newest job",()=>{
  const jobs=[{id:"newest",content:"<summary>20%</summary>"},{id:"older",content:"<summary>Stored</summary>"}];
  let view=updatePreparationJobs(undefined,jobs,[],"Empty");
  assert.equal(view.state.openById.get("newest"),true);
  assert.equal(view.state.openById.get("older"),false);
  const userChoices=[{id:"newest",open:false},{id:"older",open:true}];
  for(let poll=0;poll<2;poll++) {
    view=updatePreparationJobs(view.state,jobs,userChoices,"Empty","older");
    assert.equal(view.markup,null,"unchanged polling must keep the existing DOM and focus");
    assert.equal(view.restoreFocusJobId,null);
    assert.deepEqual([...view.state.openById],[['newest',false],['older',true]]);
  }
  const progress=[{...jobs[0],content:"<summary>60%</summary>"},jobs[1]];
  view=updatePreparationJobs(view.state,progress,userChoices,"Empty","older");
  assert.match(view.markup,/data-job-id="older" open/);
  assert.doesNotMatch(view.markup,/data-job-id="newest" open/);
  assert.equal(view.restoreFocusJobId,"older","changed content restores the same job summary focus");
  view=updatePreparationJobs(view.state,[{id:"third",content:"<summary>Queued</summary>"},...progress],userChoices,"Empty","older");
  assert.deepEqual([...view.state.openById],[['third',true],['newest',false],['older',true]]);
  assert.equal(view.restoreFocusJobId,"older");
  const observed=[...view.state.openById].map(([id,open])=>({id,open}));
  view=updatePreparationJobs(view.state,[{id:"third",content:"<summary>Queued</summary>"},...progress],observed,"Empty","older");
  assert.equal(view.markup,null,"new disclosure defaults must not cause another rerender on the next poll");
});

test("job identities are escaped and removed jobs cannot retain disclosure state or focus",()=>{
  const id='job"<&';
  let view=updatePreparationJobs(undefined,[{id,content:"<summary>Stored</summary>"}],[],"Empty",id);
  assert.match(view.markup,/data-job-id="job&quot;&lt;&amp;"/);
  view=updatePreparationJobs(view.state,[],[{id,open:true}],"Empty",id);
  assert.equal(view.markup,"Empty");
  assert.equal(view.state.openById.size,0);
  assert.equal(view.restoreFocusJobId,null);
});
