(() => {
  'use strict';
  const form = document.querySelector('#filters');
  const status = document.querySelector('#feedback-status');
  const results = document.querySelector('#feedback-results');
  const exportButton = document.querySelector('#export');
  let applied = new URLSearchParams(); let page = 1; let pages = 1; let request = 0;
  const labels = ['Definitely', 'Probably', 'Probably not', 'Definitely not'];
  const sourceLabels = { reddit:'Reddit', family:'Family', altalab:'AltaLab', direct:'Direct' };
  const sourceName = source => Object.hasOwn(sourceLabels,source) ? sourceLabels[source] : source;
  function el(tag, text, cls) { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (cls) node.className = cls; return node; }
  function metric(parent, label, value, note, accent) {
    const card = el('article', undefined, `summary-card${accent ? ' accent' : ''}`);
    card.append(el('p', label, 'summary-label'), el('strong', value), el('p', note, 'summary-copy')); parent.append(card);
  }
  function render(data) {
    const summary = document.querySelector('#summary'); summary.replaceChildren();
    metric(summary, 'Total responses', data.overall.total, 'Matching the active filters');
    const comprehension=data.overall.comprehension;
    metric(summary, 'Understood Zippi correctly', comprehension.correct.percent === null ? '—' : `${comprehension.correct.percent}%`, `${comprehension.correct.count} of ${comprehension.answered} choice responses`, true);
    const breakdown=document.querySelector('#comprehension-breakdown'); breakdown.replaceChildren();
    document.querySelector('#comprehension-note').textContent = `Percentages use ${comprehension.answered} responses to the choice question, within the active filters. ${comprehension.notAsked} earlier responses were not asked this question and are excluded.`;
    for (const choice of Object.values(comprehension.choices)) {
      const row=el('div'); row.append(el('dt',choice.label),el('dd',`${choice.count} · ${choice.percent === null ? '—' : choice.percent+'%'}`)); breakdown.append(row);
    }
    for (const label of labels) { const value = data.overall.likelihoods[label]; metric(summary, label, `${value.percent}%`, `${value.count} ${value.count===1 ? 'response' : 'responses'}`); }
    metric(summary, 'Definitely + Probably', `${data.overall.positive.percent}%`, `${data.overall.positive.count} responses`, true);
    metric(summary, 'Recent flight shoppers', `${data.overall.recent.percent}%`, `${data.overall.recent.count} of ${data.overall.total} responses`);
    const shoppers = document.querySelector('#shoppers'); shoppers.replaceChildren();
    for (const [label, value] of [['Responses',data.shoppers.total],['Definitely',`${data.shoppers.likelihoods.Definitely.percent}%`],['Probably',`${data.shoppers.likelihoods.Probably.percent}%`],['Definitely + Probably',`${data.shoppers.positive.percent}%`]]) {
      const item = el('div'); item.append(el('strong',value), el('span',label)); shoppers.append(item);
    }
    const sources = document.querySelector('#sources'); sources.replaceChildren();
    if (!data.sources.length) sources.append(el('p','No matching responses yet.'));
    for (const source of data.sources) {
      const item = el('article'); item.append(el('strong',sourceName(source.source)),el('p',`${source.total} ${source.total===1 ? 'response' : 'responses'} · ${source.positive.percent}% Definitely + Probably`));
      for (const label of labels) item.append(el('p',`${label}: ${source.likelihoods[label].count} (${source.likelihoods[label].percent}%)`));
      sources.append(item);
    }
    const sourceSelect = document.querySelector('#source'); const selected = sourceSelect.value;
    sourceSelect.replaceChildren(new Option('All sources',''));
    for (const source of [...new Set([...data.sourceOptions, selected].filter(Boolean))]) sourceSelect.add(new Option(sourceName(source),source));
    sourceSelect.value = selected;
    const tbody = document.querySelector('#responses'); tbody.replaceChildren();
    const names = ['Date / time','Source','Comprehension / own words','Likelihood to use','Additional comments','Recent flight shopper'];
    function appendAnswer(parent,value) {
      if (value.length > 180) {
        const details=el('details'); details.append(el('summary',value.slice(0,140)+'… Read full answer'),el('p',value)); parent.append(details);
      } else parent.append(el('p',value,'answer-text'));
    }
    for (const row of data.rows) {
      const tr=el('tr');
      const values=[new Date(row.submitted_at).toLocaleString(),sourceName(row.source),'',row.likelihood,row.additional_comments || '—',row.recent_flight_shopper ? 'Yes' : 'No'];
      values.forEach((value,index)=>{
        const td=el('td'); td.dataset.label=names[index];
        if (index===2) {
          td.append(el('p',comprehension.choices[row.comprehension_choice]?.label || 'Not asked (earlier form)','choice-description'));
          if (row.own_words) { td.append(el('p','Own words','answer-caption')); appendAnswer(td,row.own_words); }
        } else if (index===4) {
          if (!row.comprehension_choice && row.additional_comments) td.append(el('p','Earlier question: Why did you choose that answer?','answer-caption'));
          appendAnswer(td,value);
        } else td.textContent=value;
        tr.append(td);
      }); tbody.append(tr);
    }
    if (!data.rows.length) { const tr=el('tr'); const td=el('td','No responses match these filters.'); td.colSpan=6; tr.append(td); tbody.append(tr); }
    page = data.page; pages = data.pages;
    document.querySelector('#page-info').textContent = `Page ${page} of ${pages} · ${data.overall.total} responses`;
    document.querySelector('#previous').disabled = page <= 1; document.querySelector('#next').disabled = page >= pages;
  }
  async function load() {
    const current = ++request; exportButton.disabled = true; results.hidden = true; status.textContent = 'Loading feedback…';
    const query = new URLSearchParams(applied); query.set('page',page);
    try {
      const response = await fetch(`/admin/api/demo-feedback?${query}`, { cache:'no-store' });
      if (response.status === 401) { location.assign('/admin/login'); return; }
      if (!response.ok) throw new Error('Could not load feedback. Check the filters or try again.');
      const data = await response.json(); if (current !== request) return;
      render(data); results.hidden = false; status.textContent = `${data.overall.total} responses match the active filters.`; exportButton.disabled = false;
    } catch (error) { if (current === request) status.textContent = error.message; }
  }
  form.addEventListener('submit',event => { event.preventDefault(); applied = new URLSearchParams(new FormData(form)); page=1; load(); });
  document.querySelector('#reset-filters').addEventListener('click',() => { form.reset(); applied=new URLSearchParams(); page=1; load(); });
  document.querySelector('#previous').addEventListener('click',() => { if(page>1) { page--; load(); } });
  document.querySelector('#next').addEventListener('click',() => { if(page<pages) { page++; load(); } });
  exportButton.addEventListener('click',async () => {
    exportButton.disabled = true; status.textContent = 'Preparing CSV for the active filters…';
    try {
      const response = await fetch(`/admin/api/demo-feedback/export.csv?${applied}`, { cache:'no-store' });
      if (response.status === 401) { location.assign('/admin/login'); return; }
      if (!response.ok || !response.headers.get('content-type')?.includes('text/csv')) throw new Error('CSV download failed. Please try again.');
      const blob = await response.blob(); const url = URL.createObjectURL(blob); const link = el('a');
      link.href=url; link.download=`zippi-demo-feedback-${new Date().toISOString().slice(0,10)}.csv`; document.body.append(link); link.click(); link.remove();
      setTimeout(()=>URL.revokeObjectURL(url),10000); status.textContent='CSV downloaded for the active filters.';
    } catch(error) { status.textContent=error.message; } finally { exportButton.disabled=false; }
  });
  load();
})();
