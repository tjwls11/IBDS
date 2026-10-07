import {$,api,element,notice,labels,progressLabels,reasonLabels,stages,order,statusClass} from './common.js';
import {selectGroups} from './report-data.js';
const groupLabels={xss:'XSS',sqli:'SQLi'};
let report=null,loadId=0;
function badge(status){return element('span',labels[status]||status,`badge ${statusClass(status)}`);}
function percent(value){return `${(value*100).toFixed(1)}%`;}
function hideErrors(){
    $('error-panel').hidden=true;
    $('error-toggle')?.setAttribute('aria-expanded','false');
    $('error-toggle')?.focus();
}
function options(id,values,title,label=(x)=>x){const select=$(id);select.replaceChildren(new Option(title,''));values.forEach(value=>select.add(new Option(label(value),value)));}
function showErrors(){ $('error-panel').hidden=false;$('errors').replaceChildren();if(!report.errors.length)$('errors').append(element('p','기록된 오류가 없습니다.','hint'));for(const error of report.errors){const row=element('div',undefined,'error-row');row.append(element('strong',`${error.target_id||'대상 미상'} · ${error.param||'파라미터 미상'}`),element('span',error.stage||'request','tag'),element('p',error.url||'URL 정보 없음'),element('p',error.error||'원인 정보 없음','reason'));if(error.case_id)row.append(element('p',error.case_id,'hint'));$('errors').append(row);}$('error-panel').scrollIntoView({block:'nearest'}); }
function renderKpis(){
    $('kpis').replaceChildren();
    const statuses=[...order,...report.statuses.filter(x=>!order.includes(x))];
    for(const status of statuses){const node=element('div',undefined,`kpi ${statusClass(status)}`);node.append(element('span',labels[status]||status),element('strong',String(report.counts[status]||0)));$('kpis').append(node);}
    const node=element('button',undefined,'kpi error-kpi error-alert');
    node.id='error-toggle';
    node.setAttribute('aria-controls','error-panel');
    node.setAttribute('aria-expanded','false');
    node.title='클릭하면 오류 상세 보기 · 더블클릭하면 접기';
    node.append(element('span','에러 · 상세 보기'),element('strong',String(report.error_count)));
    node.onclick=()=>{showErrors();node.setAttribute('aria-expanded','true');};
    node.ondblclick=hideErrors;
    $('kpis').append(node);
    const rates=report.rates;
    $('rates').hidden=!rates;
    if(rates)$('rates').textContent=`검사 지점 ${rates.points}개, 완료율 ${percent(rates.completion)}, 검토 필요율 ${percent(rates.inconclusive)}, 침묵 음성 ${rates.silent_negatives}건`;
}
// 진행 상태와 대표 사유 한 줄
function progressText(progress,reason){return `${progressLabels[progress]||progress||'진행 상태 없음'}${reason?`, 사유: ${reasonLabels[reason]||reason}`:''}`;}
// 근거 카드 하나 (판정 기록 또는 사유만 남은 시도)
function card(item){
    const detail=element('div',undefined,'finding');const head=element('div',undefined,'finding-head');
    head.append(item.final_status?badge(item.final_status):element('span',progressLabels[item.progress_status]||'기록','badge unknown'),element('strong',item.category||'기법 정보 없음'));
    if(item.case_id)head.append(element('code',item.case_id,'hint'));
    detail.append(head);
    const browser=item.browser&&`${item.browser.executed?'실행됨':'실행 안 됨'}${item.browser.evidence?`, ${item.browser.evidence}`:''}`;
    const facts=[['진행 상태',progressText(item.progress_status,item.reason)],['보충',item.reason_note],['기대 식별값',item.exec_token],
        ['브라우저 확인',browser],['저장 표식',item.probe_marker],['재조회 주소',item.revisit_url],
        ['재조회 반사',item.revisit_found===null||item.revisit_found===undefined?null:item.revisit_found?'확인':'없음']].filter(([,value])=>value);
    const list=element('dl',undefined,'facts');
    for(const [name,value] of facts)list.append(element('dt',name),element('dd',String(value)));
    detail.append(list);
    if(item.payload!==null&&item.payload!==undefined)detail.append(element('pre',item.payload));
    if(item.evidence)detail.append(element('p',item.evidence));
    const raw=element('details');raw.append(element('summary','판정 상세 데이터'),element('pre',JSON.stringify(item.raw,null,2)));detail.append(raw);
    return detail;
}
function renderGroups(){
    if(!report)return;
    const status=$('status-filter').value,vulnType=$('technique-filter').value;
    const groups=selectGroups(report.groups,status,vulnType,$('sort').value);
    $('groups').replaceChildren();$('result-count').textContent=`검사 지점 ${groups.length}개, 근거 ${groups.reduce((n,g)=>n+g.items.length,0)}개`;
    $('empty').hidden=groups.length>0;
    const filtered=report.groups.length>0;
    $('empty').querySelector('h2').textContent=filtered?'조건에 맞는 결과가 없습니다':'아직 스캔 결과가 없습니다';
    $('empty').querySelector('p').textContent=filtered?'판정기준이나 취약점 종류 필터를 변경해 보세요.':report.error_count?'오류 상세에서 검사하지 못한 항목을 확인하세요.':'스캔을 실행하면 검사 지점별 결과가 표시됩니다.';
    for(const group of groups){
        const block=element('details',undefined,'result-group');const summary=element('summary');const title=element('div',undefined,'group-name');
        const name=element('div');name.append(element('strong',group.param),element('span',groupLabels[group.vuln_type]||group.vuln_type,'tag'));
        title.append(name,element('div',`${group.method} ${group.url||group.target_id}`,'group-url'),element('div',progressText(group.progress_status,group.reason),'group-url'));
        summary.append(badge(group.final_status),title,element('span',`근거 ${group.items.length}개`,'group-total'));block.append(summary);
        if(!group.items.length)block.append(element('p',group.discovery_filtered?`Discovery가 공격 후보 ${group.discovery_filtered}개를 모두 걸러서 보낸 시도가 없습니다.`:'남은 근거가 없습니다.','finding hint'));
        for(const item of group.items)block.append(card(item));
        $('groups').append(block);
    }
}
async function loadReport(run){
    const id=++loadId;
    try{const data=await api(`/api/results${run?'?run='+encodeURIComponent(run):''}`);if(id!==loadId)return;report=data;
        options('status-filter',report.statuses,'모든 판정',x=>labels[x]||x);options('technique-filter',report.filter_groups,'모든 종류',x=>groupLabels[x]||x);$('sort').value='severity';$('error-panel').hidden=true;
        $('run-meta').textContent=report.run?`${stages[report.meta.stage||'legacy']||report.meta.stage} · ${report.run}`:'저장된 실행 기록이 없습니다.';
        $('run-error').hidden=!report.meta.error;$('run-error').textContent=report.meta.error||'';
        $('export').hidden=!report.run;
        if(report.run){$('export').href=`/api/results/export?run=${encodeURIComponent(report.run)}`;$('runs').value=report.run;history.replaceState(null,'',`/scan?run=${encodeURIComponent(report.run)}`);}
        notice('');renderKpis();renderGroups();
    }catch(error){notice(error.message,true);}
}
async function refresh(){try{const selected=$('runs').value||new URLSearchParams(location.search).get('run');const data=await api('/api/scans');$('runs').replaceChildren();data.runs.forEach(run=>$('runs').add(new Option(`${run.label} · ${stages[run.stage]||run.stage}`,run.id)));if(!data.runs.length)$('runs').add(new Option('저장된 실행 없음',''));await loadReport(data.runs.some(x=>x.id===selected)?selected:data.runs[0]?.id);}catch(error){notice(error.message,true);}}
for(const id of ['status-filter','technique-filter','sort'])$(id).onchange=renderGroups;
$('reset').onclick=()=>{$('status-filter').value='';$('technique-filter').value='';$('sort').value='severity';renderGroups();};
$('runs').onchange=()=>loadReport($('runs').value);$('refresh').onclick=refresh;
$('close-errors').onclick=hideErrors;
$('error-panel').ondblclick=hideErrors;
$('error-panel').title='더블클릭하면 오류 상세 접기';
$('runs').replaceChildren();await refresh();
