(() => {
  'use strict';
  const form = document.querySelector('#filters');
  const status = document.querySelector('#feedback-status');
  const results = document.querySelector('#feedback-results');
  const exportButton = document.querySelector('#export');
  const currentVersion = 'combined_demo_v4';
  const isCombined = version => ['combined_demo_v4', 'combined_demo_v3'].includes(version);
  const versions = { combined_demo_v4:'Current · Combined demo v4', combined_demo_v3:'Previous · Combined demo v3', multiple_choice_v2:'Historical · Flight demo choice form', free_text_v1:'Historical · Flight demo original form' };
  const labels = ['Definitely', 'Probably', 'Probably not', 'Definitely not'];
  const clarityLabels = ['Very clear', 'Somewhat clear', 'Not very clear', 'Not clear at all'];
  const sourceLabels = { reddit:'Reddit', family:'Family', altalab:'AltaLab', direct:'Direct' };
  const sourceName = source => Object.hasOwn(sourceLabels, source) ? sourceLabels[source] : source;
  const percent = value => value === null || value === undefined ? '—' : `${value}%`;
  let applied = new URLSearchParams(new FormData(form)); let page = 1; let pages = 1; let request = 0;
  function el(tag, text, cls) { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (cls) node.className = cls; return node; }
  function metric(parent, label, value, note, accent) {
    const card = el('article', undefined, `summary-card${accent ? ' accent' : ''}`);
    card.append(el('p', label, 'summary-label'), el('strong', value), el('p', note, 'summary-copy')); parent.append(card);
  }
  function breakdown(selector, values) {
    const parent = document.querySelector(selector); parent.replaceChildren();
    for (const [label, value] of values) {
      const row = el('div'); row.append(el('dt', label), el('dd', `${value.count} · ${percent(value.percent)}`)); parent.append(row);
    }
  }
  function answer(parent, value) {
    if (value.length > 180) {
      const details = el('details'); details.append(el('summary', value.slice(0,140) + '… Read full answer'), el('p', value)); parent.append(details);
    } else parent.append(el('p', value, 'answer-text'));
  }
  function setFilterMode() {
    const current = isCombined(form.elements.survey_version.value);
    for (const [name, enabled] of [['clarity', current], ['booked', current], ['recent', !current]]) {
      document.querySelector(`#${name}-filter`).hidden = !enabled;
      form.elements[name].disabled = !enabled;
      if (!enabled) form.elements[name].value = '';
    }
  }
  function render(data) {
    const current = data.surveyVersion === currentVersion;
    const combined = isCombined(data.surveyVersion);
    const overall = data.overall;
    const totals = document.querySelector('#response-totals'); totals.replaceChildren();
    metric(totals, 'Total responses · all surveys', data.totals.all, 'All demo versions and historical package responses. Counts submissions, not unique people. Source and date filters only.');
    metric(totals, 'Current survey responses', data.totals.current, 'Combined demo v4 only. Source and date filters only.', true);
    document.querySelector('#survey-title').textContent = versions[data.surveyVersion];
    document.querySelector('#survey-note').textContent = current
      ? 'Survey version: combined_demo_v4. These results include only the current survey within all active filters. Previous versions retain their original questions and answers.'
      : combined ? 'Survey version: combined_demo_v3. Previous combined demo, with its original question wording and submitted answers preserved. These responses are separate from v4.'
      : `Survey version: ${data.surveyVersion}. These are earlier flight-demo responses, kept separate from the current survey. Exact question wording was not saved with each response; the likelihood wording changed without a version boundary, so its exact wording cannot be attributed to individual historical answers.`;
    const summary = document.querySelector('#summary'); summary.replaceChildren();
    metric(summary, current ? 'Current responses · filtered' : combined ? 'Previous responses · filtered' : 'Historical responses · filtered', overall.total, 'Selected survey, matching all active filters');
    metric(summary, 'Definitely + Probably', percent(overall.positive.percent), `${overall.positive.count} responses in the selected survey`, true);
    document.querySelector('#comprehension-panel').hidden = data.surveyVersion === 'free_text_v1';
    document.querySelector('#booked-panel').hidden = !combined;
    document.querySelector('#validation-panel').hidden = !combined;
    document.querySelector('#shoppers-panel').hidden = combined;
    document.querySelector('#likelihood-title').textContent = current
      ? 'If this feature were available on a travel website or app you already use, how likely would you be to use it?'
      : combined ? 'Based on what you saw, how likely would you be to use Zippi when planning your next trip?'
      : 'Earlier likelihood responses';
    document.querySelector('#likelihood-note').textContent = `${overall.total} responses in the selected survey, within the active filters.${combined ? '' : ' Historical wording is not reliably attributable to individual responses.'}`;
    breakdown('#likelihood-breakdown', labels.map(label => [label, overall.likelihoods[label]]));
    if (combined) {
      document.querySelector('#comprehension-title').textContent = 'How clear is it what Zippi does?';
      document.querySelector('#comprehension-note').textContent = `Percentages use ${overall.total} selected-survey responses within the active filters.`;
      breakdown('#comprehension-breakdown', clarityLabels.map(label => [label, overall.clarity[label]]));
      document.querySelector('#booked-note').textContent = `${overall.booked.answered} selected-survey responses answered this question within the active filters.`;
      breakdown('#booked-breakdown', [['Yes', overall.booked.yes], ['No', overall.booked.no]]);
      document.querySelector('#validation-definition').textContent = 'Answered Yes to booking travel in the last 12 months and Definitely or Probably to ' + (current ? 'using this feature on a travel website or app already used.' : 'using Zippi when planning the next trip.');
      const validation = document.querySelector('#validation'); validation.replaceChildren();
      for (const [label, value] of [['Responses', overall.validation.count], ['Of booking-question answers', percent(overall.validation.percent)]]) {
        const item = el('div'); item.append(el('strong', value), el('span', label)); validation.append(item);
      }
      document.querySelector('#validation-note').textContent = `${overall.validation.count} of ${overall.validation.denominator} selected-survey respondents who answered the booking question, within all active filters. The denominator includes both Yes and No answers.`;
    } else {
      const comprehension = overall.comprehension;
      document.querySelector('#comprehension-title').textContent = 'Earlier understanding of Zippi';
      document.querySelector('#comprehension-note').textContent = `Percentages use ${comprehension.answered} earlier choice responses within the active filters. ${comprehension.notAsked} responses were not asked the choice question and are excluded.`;
      breakdown('#comprehension-breakdown', Object.values(comprehension.choices).map(choice => [choice.label, choice]));
      if (data.surveyVersion === 'multiple_choice_v2') metric(summary, 'Earlier correct choice', percent(comprehension.correct.percent), `${comprehension.correct.count} of ${comprehension.answered} earlier choice responses`);
      metric(summary, 'Earlier recent flight shoppers', percent(overall.recent.percent), `${overall.recent.count} of ${overall.total} historical responses`);
      const shoppers = document.querySelector('#shoppers'); shoppers.replaceChildren();
      for (const [label, value] of [['Responses', data.shoppers.total], ['Definitely', percent(data.shoppers.likelihoods.Definitely.percent)], ['Probably', percent(data.shoppers.likelihoods.Probably.percent)], ['Definitely + Probably', percent(data.shoppers.positive.percent)]]) {
        const item = el('div'); item.append(el('strong', value), el('span', label)); shoppers.append(item);
      }
    }
    document.querySelector('#comments-panel').hidden = !current;
    const comments = document.querySelector('#comments'); comments.replaceChildren();
    if (current) {
      const written = (data.comments || []).filter(row => typeof row.comment === 'string' && row.comment.trim());
      document.querySelector('#comments-note').textContent = `${data.commentCount || 0} nonblank comments within the active filters. Showing ${written.length} on response page ${data.page} of ${data.pages}; use the response pagination below to see more. Times shown in your local timezone.`;
      for (const row of written) {
        const item = el('article');
        item.append(el('p', row.comment, 'answer-text'), el('p', `${new Date(row.submitted_at).toLocaleString()} · ${sourceName(row.source)} · Response ${row.response_id}`, 'comment-meta'));
        comments.append(item);
      }
      if (!written.length) comments.append(el('p', 'No written feedback on this response page.'));
    }
    const sources = document.querySelector('#sources'); sources.replaceChildren();
    if (!data.sources.length) sources.append(el('p', 'No matching responses yet.'));
    for (const source of data.sources) {
      const item = el('article'); item.append(el('strong', sourceName(source.source)), el('p', `${source.total} ${source.total === 1 ? 'response' : 'responses'} · ${percent(source.positive.percent)} Definitely + Probably`));
      for (const label of labels) item.append(el('p', `${label}: ${source.likelihoods[label].count} (${percent(source.likelihoods[label].percent)})`));
      sources.append(item);
    }
    const sourceSelect = document.querySelector('#source'); const selected = sourceSelect.value;
    sourceSelect.replaceChildren(new Option('All sources', ''));
    for (const source of [...new Set([...data.sourceOptions, selected].filter(Boolean))]) sourceSelect.add(new Option(sourceName(source), source));
    sourceSelect.value = selected;
    const names = combined
      ? ['Date / time', 'Source', 'Zippi clarity', 'Likelihood to use Zippi', 'Booked travel in last 12 months']
      : ['Date / time', 'Source', 'Earlier comprehension / own words', 'Earlier likelihood', 'Earlier written response', 'Earlier recent flight shopper'];
    const headings = document.querySelector('#response-headings'); headings.replaceChildren();
    for (const name of names) { const th = el('th', name); th.scope = 'col'; headings.append(th); }
    const tbody = document.querySelector('#responses'); tbody.replaceChildren();
    for (const row of data.rows) {
      const tr = el('tr');
      const values = combined
        ? [new Date(row.submitted_at).toLocaleString(), sourceName(row.source), row.clarity, row.use_likelihood, row.booked_travel_last_12_months ? 'Yes' : 'No']
        : [new Date(row.submitted_at).toLocaleString(), sourceName(row.source), '', row.likelihood, row.additional_comments || '—', row.recent_flight_shopper ? 'Yes' : 'No'];
      values.forEach((value, index) => {
        const td = el('td'); td.dataset.label = names[index];
        if (!combined && index === 2) {
          td.append(el('p', overall.comprehension.choices[row.comprehension_choice]?.label || 'Choice question not asked (original form)', 'choice-description'));
          if (row.own_words) { td.append(el('p', 'Earlier own-words response', 'answer-caption')); answer(td, row.own_words); }
        } else if (!combined && index === 4) {
          td.append(el('p', row.comprehension_choice ? 'Earlier additional comments' : 'Earlier reason for likelihood answer', 'answer-caption'));
          answer(td, value);
        } else td.textContent = value;
        tr.append(td);
      }); tbody.append(tr);
    }
    if (!data.rows.length) { const tr = el('tr'); const td = el('td', 'No responses match these filters.'); td.colSpan = names.length; tr.append(td); tbody.append(tr); }
    page = data.page; pages = data.pages;
    document.querySelector('#page-info').textContent = `Page ${page} of ${pages} · ${overall.total} responses`;
    document.querySelector('#previous').disabled = page <= 1; document.querySelector('#next').disabled = page >= pages;
  }
  async function load() {
    const current = ++request; exportButton.disabled = true; results.hidden = true; status.textContent = 'Loading feedback…';
    const query = new URLSearchParams(applied); query.set('page', page);
    try {
      const response = await fetch(`/admin/api/demo-feedback?${query}`, { cache:'no-store' });
      if (response.status === 401) { location.assign('/admin/login'); return; }
      if (!response.ok) throw new Error('Could not load feedback. Check the filters or try again.');
      const data = await response.json(); if (current !== request) return;
      if (data.surveyVersion !== applied.get('survey_version')) throw new Error('Survey version did not match. Please reload before reviewing results.');
      render(data); results.hidden = false; status.textContent = `${data.overall.total} responses match the active filters in ${versions[data.surveyVersion]}.`; exportButton.disabled = false;
    } catch (error) { if (current === request) status.textContent = error.message; }
  }
  function applyFilters() { setFilterMode(); applied = new URLSearchParams(new FormData(form)); page = 1; load(); }
  form.addEventListener('submit', event => { event.preventDefault(); applyFilters(); });
  form.elements.survey_version.addEventListener('change', applyFilters);
  document.querySelector('#reset-filters').addEventListener('click', () => { form.reset(); applyFilters(); });
  document.querySelector('#previous').addEventListener('click', () => { if (page > 1) { page--; load(); } });
  document.querySelector('#next').addEventListener('click', () => { if (page < pages) { page++; load(); } });
  exportButton.addEventListener('click', async () => {
    const exportQuery = new URLSearchParams(applied);
    const exportRequest = request;
    exportButton.disabled = true; status.textContent = 'Preparing CSV for the selected survey and active filters…';
    try {
      const response = await fetch(`/admin/api/demo-feedback/export.csv?${exportQuery}`, { cache:'no-store' });
      if (response.status === 401) { location.assign('/admin/login'); return; }
      if (!response.ok || !response.headers.get('content-type')?.includes('text/csv')) throw new Error('CSV download failed. Please try again.');
      const blob = await response.blob(); const url = URL.createObjectURL(blob); const link = el('a');
      link.href = url; link.download = `zippi-demo-feedback-${exportQuery.get('survey_version')}-${new Date().toISOString().slice(0,10)}.csv`; document.body.append(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
      if (exportRequest === request) status.textContent = 'CSV downloaded for the selected survey and active filters.';
    } catch (error) { if (exportRequest === request) status.textContent = error.message; }
    finally { if (exportRequest === request) exportButton.disabled = false; }
  });
  load();
})();
