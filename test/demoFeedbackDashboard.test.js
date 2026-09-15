const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const script = fs.readFileSync(path.join(__dirname, '../admin/public/demo-feedback.js'), 'utf8');
const html = fs.readFileSync(path.join(__dirname, '../admin/public/demo-feedback.html'), 'utf8');
const tick = () => new Promise(resolve => setImmediate(resolve));

// A small DOM adapter exercises the shipped browser script without a browser dependency.
class Element {
  constructor(tag = 'div', value = '') { this.tagName = tag; this.value = value; this.children = []; this.listeners = {}; this.dataset = {}; this.disabled = false; this.hidden = false; this._text = ''; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(' '); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this._text = ''; this.children = children; }
  add(child) { this.append(child); }
  addEventListener(event, callback) { this.listeners[event] = callback; }
  async trigger(event) { await this.listeners[event]?.({ preventDefault() {} }); await tick(); }
  click() { this.clicked = true; }
  remove() { this.removed = true; }
}
function harness(data) {
  const nodes = Object.fromEntries([...html.matchAll(/id="([^"]+)"/g)].map(match => ['#' + match[1], new Element()]));
  const form = nodes['#filters'];
  form.elements = Object.fromEntries(['survey_version', 'source', 'likelihood', 'clarity', 'booked', 'recent', 'from', 'to', 'sort'].map(name => [name, new Element('select')]));
  form.elements.survey_version = nodes['#survey-version'];
  form.elements.source = nodes['#source'];
  form.reset = () => { Object.values(form.elements).forEach(field => { field.value = ''; }); form.elements.survey_version.value = 'combined_demo_v3'; form.elements.sort.value = 'newest'; };
  form.reset(); form.elements.recent.disabled = true;
  class FormData { constructor(value) { this.values = Object.entries(value.elements).filter(([, field]) => !field.disabled).map(([name, field]) => [name, field.value]); } [Symbol.iterator]() { return this.values[Symbol.iterator](); } }
  class Option extends Element { constructor(label, value) { super('option', value); this.textContent = label; } }
  const body = new Element('body');
  const state = { data, calls: [], redirects: [], nodes, form, body, status: 200 };
  const context = { document: { querySelector: selector => { assert.ok(nodes[selector], 'Unknown node ' + selector); return nodes[selector]; }, createElement: tag => new Element(tag), body }, FormData, Option, URLSearchParams, URL: { createObjectURL: () => 'blob:local-fixture', revokeObjectURL() {} }, setTimeout() {}, location: { assign: value => state.redirects.push(value) }, fetch: async (url, options) => {
    state.calls.push({ url, options });
    if (url.includes('export.csv')) return { ok:true, headers:{get:()=>'text/csv'}, blob:async()=>new Blob(['fixture']) };
    return { status:state.status, ok:state.status === 200, json:async()=>state.data };
  } };
  vm.runInNewContext(script, context);
  return state;
}
const values = ['Definitely', 'Probably', 'Probably not', 'Definitely not'];
const stats = (counts, total) => Object.fromEntries(values.map((label, index) => [label, { count:counts[index], percent:total ? counts[index] / total * 100 : null }]));
function current() {
  return { surveyVersion:'combined_demo_v3', totals:{all:40,current:9,free_text_v1:10,multiple_choice_v2:12,package_v1:9}, overall:{ total:5, likelihoods:stats([2,2,1,0],5), positive:{count:4,percent:80}, clarity:Object.fromEntries(['Very clear','Somewhat clear','Not very clear','Not clear at all'].map((label,index)=>[label,{count:[2,2,1,0][index],percent:[40,40,20,0][index]}])), booked:{answered:5,yes:{count:4,percent:80},no:{count:1,percent:20}}, validation:{count:3,percent:60,denominator:5} }, sourceOptions:['family'], sources:[], rows:[{submitted_at:'2026-09-15T12:00:00Z',source:'family',clarity:'Very clear',use_likelihood:'Definitely',booked_travel_last_12_months:true}], page:1,pages:2 };
}
function historical(version='multiple_choice_v2') {
  const result=current();
  result.surveyVersion=version;
  result.overall={ total:2, likelihoods:stats([1,0,1,0],2),positive:{count:1,percent:50},recent:{count:1,percent:50},comprehension:{answered:version==='free_text_v1'?0:2,notAsked:version==='free_text_v1'?2:0,correct:{count:1,percent:50},choices:{travel:{label:'Original recorded choice',count:1,percent:50}}} };
  result.shoppers={total:1,likelihoods:stats([1,0,0,0],1),positive:{count:1,percent:100}};
  result.rows=[{submitted_at:'2026-09-13T12:00:00Z',source:'family',own_words:'<script>Historical text</script>',additional_comments:'Original reason',likelihood:'Definitely',comprehension_choice:version==='free_text_v1'?null:'travel',recent_flight_shopper:true}];
  return result;
}

test('current view uses an explicit version, separate totals and the full booking-answer denominator', async () => {
  const state=harness(current()); await tick();
  assert.equal(new URL(state.calls[0].url,'http://local').searchParams.get('survey_version'),'combined_demo_v3');
  assert.equal(state.nodes['#feedback-results'].hidden,false);
  assert.match(state.nodes['#response-totals'].textContent,/40/);
  assert.match(state.nodes['#response-totals'].textContent,/9/);
  assert.match(state.nodes['#response-totals'].textContent,/not unique people/);
  assert.match(state.nodes['#summary'].textContent,/Current responses · filtered 5/);
  assert.match(state.nodes['#validation'].textContent,/3 Responses 60% Of booking-question answers/);
  assert.match(state.nodes['#validation-note'].textContent,/3 of 5/);
  assert.match(state.nodes['#validation-note'].textContent,/both Yes and No/);
  assert.equal(state.nodes['#comprehension-title'].textContent,'How clear is it what Zippi does?');
  assert.match(state.nodes['#likelihood-title'].textContent,/planning your next trip\?/);
  assert.equal(state.nodes['#responses'].children[0].children.length,5);
  assert.match(state.nodes['#responses'].textContent,/Very clear Definitely Yes/);
  assert.equal(state.nodes['#shoppers-panel'].hidden,true);
});

test('switching historical versions keeps earlier answers and exports separate from current questions', async () => {
  const state=harness(current()); await tick();
  state.form.elements.clarity.value='Very clear';state.form.elements.booked.value='yes';
  state.form.elements.survey_version.value='free_text_v1';state.data=historical('free_text_v1');
  await state.form.elements.survey_version.trigger('change');
  const query=new URL(state.calls.at(-1).url,'http://local').searchParams;
  assert.equal(query.get('survey_version'),'free_text_v1');assert.equal(query.get('page'),'1');
  assert.equal(query.has('clarity'),false);assert.equal(query.has('booked'),false);assert.equal(query.has('recent'),true);
  assert.equal(state.nodes['#comprehension-panel'].hidden,true);assert.equal(state.nodes['#booked-panel'].hidden,true);assert.equal(state.nodes['#validation-panel'].hidden,true);
  assert.equal(state.nodes['#shoppers-panel'].hidden,false);
  assert.match(state.nodes['#survey-note'].textContent,/Exact question wording was not saved/);
  assert.match(state.nodes['#survey-note'].textContent,/likelihood wording changed without a version boundary/);
  assert.match(state.nodes['#response-headings'].textContent,/Earlier likelihood/);
  assert.match(state.nodes['#responses'].textContent,/<script>Historical text<\/script>/);
  assert.match(state.nodes['#responses'].textContent,/Choice question not asked/);
  assert.equal(state.nodes['#responses'].children[0].children.length,6);
  await state.nodes['#export'].trigger('click');
  assert.equal(new URL(state.calls.at(-1).url,'http://local').searchParams.get('survey_version'),'free_text_v1');
  assert.match(state.body.children.at(-1).download,/free_text_v1/);
  state.form.elements.survey_version.value='multiple_choice_v2';state.data=historical();await state.form.elements.survey_version.trigger('change');
  assert.equal(state.nodes['#comprehension-panel'].hidden,false);assert.match(state.nodes['#responses'].textContent,/Original recorded choice/);
  state.data=current();await state.nodes['#reset-filters'].trigger('click');
  assert.equal(new URL(state.calls.at(-1).url,'http://local').searchParams.get('survey_version'),'combined_demo_v3');
  assert.equal(state.form.elements.recent.disabled,true);assert.equal(state.form.elements.booked.disabled,false);
});

test('pagination and filters retain the chosen survey, and mismatched data fails closed', async () => {
  const state=harness(current());await tick();
  state.form.elements.source.value='family';state.form.elements.booked.value='yes';await state.form.trigger('submit');
  await state.nodes['#next'].trigger('click');
  const query=new URL(state.calls.at(-1).url,'http://local').searchParams;
  assert.equal(query.get('page'),'2');assert.equal(query.get('booked'),'yes');assert.equal(query.get('source'),'family');assert.equal(query.get('survey_version'),'combined_demo_v3');
  state.data=historical();await state.form.trigger('submit');
  assert.equal(state.nodes['#feedback-results'].hidden,true);assert.equal(state.nodes['#export'].disabled,true);
  assert.match(state.nodes['#feedback-status'].textContent,/Survey version did not match/);
});

test('empty current results show no fabricated percentage and signed-out responses redirect to the existing login', async () => {
  const data=current();data.overall.total=0;data.overall.validation={count:0,percent:null,denominator:0};data.rows=[];
  const state=harness(data);await tick();
  assert.match(state.nodes['#validation'].textContent,/—/);assert.match(state.nodes['#responses'].textContent,/No responses match/);
  state.status=401;await state.form.trigger('submit');assert.deepEqual(state.redirects,['/admin/login']);
});
