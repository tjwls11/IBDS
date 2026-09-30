import {$,api,element,notice} from './common.js';
let nextId=0;
function updateEmpty(){ $('override-empty').hidden=$('overrides').children.length>0; }
function addRow(from='',to='') {
    const row=element('div',undefined,'override-row');
    const id=++nextId;
    for(const [name,label,value] of [['from','원본 주소 (A)',from],['to','재방문 주소 (B)',to]]) {
        if(name==='to')row.append(element('span','→','override-arrow'));
        const field=element('div'); const title=element('label',label); title.htmlFor=`${name}-${id}`;
        const input=element('input'); input.type='url';input.required=true;input.id=title.htmlFor;input.value=value;input.placeholder='https://example.com/page';input.dataset.field=name;input.spellcheck=false;
        field.append(title,input);row.append(field);
    }
    const remove=element('button','삭제','secondary remove');remove.type='button';remove.setAttribute('aria-label',`재방문 주소 ${id} 삭제`);remove.onclick=()=>{row.remove();updateEmpty();};row.append(remove);$('overrides').append(row);updateEmpty();return row;
}
function syncAjax(){ const on=$('ajax-spider').checked; $('ajax-random').disabled=!on; $('ajax-timeout').disabled=!on; }  // Ajax Spider를 켠 경우에만 하위 설정 활성화
$('ajax-spider').onchange=syncAjax;
$('add').onclick=()=>addRow().querySelector('input').focus();
$('settings').onsubmit=async(event)=>{
    event.preventDefault();$('save').disabled=true;
    try {
        const pairs={};
        for(const row of $('overrides').children){ const from=row.querySelector('[data-field=from]').value.trim();const to=row.querySelector('[data-field=to]').value.trim();if(Object.hasOwn(pairs,from))throw new Error('같은 원본 주소가 중복되어 있습니다.');pairs[from]=to; }
        await api('/api/config',{target_url:$('target').value.trim(),revisit_urls:pairs,ajax_spider:$('ajax-spider').checked,ajax_random_inputs:$('ajax-random').checked,ajax_timeout:Number($('ajax-timeout').value)||600});notice('설정을 저장했습니다. 실행 화면에서 스캔을 시작할 수 있습니다.');$('saved').textContent=`마지막 저장 · ${new Date().toLocaleTimeString('ko-KR')}`;
    }catch(error){notice(error.message,true);}finally{$('save').disabled=false;}
};
try{const cfg=await api('/api/config');$('target').value=cfg.target_url;$('ajax-spider').checked=cfg.ajax_spider;$('ajax-random').checked=cfg.ajax_random_inputs;$('ajax-timeout').value=cfg.ajax_timeout;syncAjax();Object.entries(cfg.revisit_urls).forEach(([a,b])=>addRow(a,b));}catch(error){notice(error.message,true);$('save').disabled=true;}
