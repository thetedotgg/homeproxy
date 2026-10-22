import {parseHostRules} from "./offline-controls.js";

export interface ScheduleWindow {
  days: number[]; startMinute: number; endMinute: number; action: "deny" | "limit";
  uploadBytesPerSecond: number; downloadBytesPerSecond: number;
}
export interface DeviceProfile {
  id: string; name: string; username: string; password: string; ips: string[];
  uploadBytesPerSecond: number; downloadBytesPerSecond: number;
  dailyQuotaMib: number; monthlyQuotaMib: number; warningPercent: number;
  allowDomains: string[]; blockDomains: string[]; noCacheDomains: string[];
  schedules: ScheduleWindow[];
}
export interface PolicySettings {
  allowDomains: string[]; blockDomains: string[]; noCacheDomains: string[];
  deviceProfiles: DeviceProfile[]; historyRetentionDays: number; scheduleUtcOffsetMinutes: number;
}
export function createProfile(): DeviceProfile {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  const id = crypto.randomUUID();
  return {id,name:"",username:`device-${id.slice(0,8)}`,password:Array.from(bytes,b=>b.toString(16).padStart(2,"0")).join(""),ips:[],uploadBytesPerSecond:0,downloadBytesPerSecond:0,dailyQuotaMib:0,monthlyQuotaMib:0,warningPercent:80,allowDomains:[],blockDomains:[],noCacheDomains:[],schedules:[]};
}
export function parseTime(value: string): number | null {
  if (!/^\d{2}:\d{2}$/.test(value)) return null;
  const [hours, minutes] = value.split(":").map(Number);
  return hours < 24 && minutes < 60 ? hours * 60 + minutes : null;
}
export function parsePrivateIps(value: string): string[] | null {
  const ips = value.split(/[\s,]+/).filter(Boolean);
  if (ips.length > 32 || new Set(ips).size !== ips.length) return null;
  return ips.every(ip => {
    if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(ip)) return false;
    const p=ip.split(".").map(Number);
    return p.every(n=>n<=255) && (p[0]===10 || p[0]===192&&p[1]===168 || p[0]===172&&p[1]>=16&&p[1]<=31);
  }) ? ips : null;
}

export function validProfiles(profiles:DeviceProfile[],sharedUsername:string):boolean {
  const ids=new Set<string>(),users=new Set<string>(),ips=new Set<string>();
  return profiles.length<=256&&profiles.every(profile=>{
    if(!/^[A-Za-z0-9_-]{1,64}$/.test(profile.id)||ids.has(profile.id)||! /^(?:[A-Za-z0-9_-]){3,32}$/.test(profile.username)||users.has(profile.username)||profile.username===sharedUsername)return false;
    ids.add(profile.id);users.add(profile.username);
    if(!profile.name.trim()||new TextEncoder().encode(profile.name).length>128||/[\x00-\x1f\x7f]/.test(profile.name)||! /^[\x21-\x7e]{16,128}$/.test(profile.password))return false;
    if(parsePrivateIps(profile.ips.join(","))===null||profile.ips.some(ip=>ips.has(ip)))return false;
    profile.ips.forEach(ip=>ips.add(ip));
    if([profile.uploadBytesPerSecond,profile.downloadBytesPerSecond].some(n=>!Number.isSafeInteger(n)||n<0||n>1e9)||[profile.dailyQuotaMib,profile.monthlyQuotaMib].some(n=>!Number.isSafeInteger(n)||n<0)||!Number.isInteger(profile.warningPercent)||profile.warningPercent<1||profile.warningPercent>100||profile.schedules.length>64)return false;
    if([profile.allowDomains,profile.blockDomains,profile.noCacheDomains].some(r=>parseHostRules(r.join(","))===null))return false;
    return profile.schedules.every(s=>s.days.length>0&&s.days.length<=7&&new Set(s.days).size===s.days.length&&s.days.every(n=>Number.isInteger(n)&&n>=1&&n<=7)&&[s.startMinute,s.endMinute].every(n=>Number.isInteger(n)&&n>=0&&n<=1439)&&s.startMinute!==s.endMinute&&[s.uploadBytesPerSecond,s.downloadBytesPerSecond].every(n=>Number.isSafeInteger(n)&&n>=0&&n<=1e9));
  });
}

type Translator = (key: string) => string;
const editorOwners=new WeakMap<object,number>();
let nextEditorOwner=0;
function ownerKey(owner:object):number {
  let id=editorOwners.get(owner);
  if(id===undefined){id=++nextEditorOwner;editorOwners.set(owner,id);}
  return id;
}
/** Editors use DOM text and values: profile names never become markup. */
export function renderProfileEditors(container: HTMLElement, profiles: DeviceProfile[], t: Translator, changed: ()=>void, busy: boolean): void {
  const rawState=new Map(Array.from(container.querySelectorAll<HTMLInputElement>("input[data-editor-key]")).map(input=>[input.dataset.editorKey!,{value:input.value,invalid:input.dataset.invalid==="true"}]));
  container.replaceChildren();
  let activeOwner:object=container;
  const labelInput = (parent:HTMLElement,key:string,value:string,update:(value:string)=>boolean,type="text") => {
    const label=document.createElement("label"); label.className="profile-field";
    const span=document.createElement("span"); span.textContent=t(key); label.append(span);
    const input=document.createElement("input"); input.type=type; input.value=value; input.disabled=busy; input.autocomplete="off";
    input.dataset.editorKey=`${ownerKey(activeOwner)}:${key}`;
    const raw=rawState.get(input.dataset.editorKey);if(raw){input.value=raw.value;input.dataset.invalid=String(raw.invalid);input.setAttribute("aria-invalid",String(raw.invalid));}
    input.addEventListener("input",()=>{const valid=update(input.value); input.dataset.invalid=String(!valid); input.setAttribute("aria-invalid",String(!valid)); changed();});
    label.append(input); parent.append(label); return input;
  };
  const numeric=(parent:HTMLElement,key:string,value:number,update:(n:number)=>void,max:number,min=0)=>labelInput(parent,key,String(value),raw=>{
    if(!/^\d+$/.test(raw)||!Number.isSafeInteger(Number(raw))||Number(raw)<min||Number(raw)>max)return false;
    update(Number(raw)); return true;
  });
  const domains=(parent:HTMLElement,key:string,values:string[],update:(v:string[])=>void)=>labelInput(parent,key,values.join(", "),raw=>{const parsed=parseHostRules(raw);if(!parsed)return false;update(parsed);return true;});
  const button=(parent:HTMLElement,key:string,action:()=>void)=>{const b=document.createElement("button");b.type="button";b.className="secondary-button";b.textContent=t(key);b.disabled=busy;b.addEventListener("click",action);parent.append(b);};
  for(const profile of profiles){
    activeOwner=profile;
    const card=document.createElement("fieldset");card.className="profile-card";
    const legend=document.createElement("legend");legend.textContent=profile.name||t("profileUnnamed");card.append(legend);
    const grid=document.createElement("div");grid.className="profile-grid";card.append(grid);
    labelInput(grid,"profileName",profile.name,v=>{profile.name=v;legend.textContent=v||t("profileUnnamed");return v.trim().length>0&&v.length<=128&&!/[\x00-\x1f\x7f]/.test(v);});
    labelInput(grid,"profileUser",profile.username,v=>{profile.username=v;return /^[A-Za-z0-9_-]{3,32}$/.test(v);});
    const keyInput=labelInput(grid,"profileKey",profile.password,v=>{profile.password=v;return v.length>=16&&v.length<=128&&/^[\x21-\x7e]+$/.test(v);},"password");
    button(keyInput.parentElement!,"profileRevealKey",()=>{keyInput.type=keyInput.type==="password"?"text":"password";});
    labelInput(grid,"profileIps",profile.ips.join(", "),v=>{const parsed=parsePrivateIps(v);if(!parsed)return false;profile.ips=parsed;return true;});
    numeric(grid,"profileUpload",profile.uploadBytesPerSecond/1024,v=>profile.uploadBytesPerSecond=v*1024,976562);
    numeric(grid,"profileDownload",profile.downloadBytesPerSecond/1024,v=>profile.downloadBytesPerSecond=v*1024,976562);
    numeric(grid,"profileDaily",profile.dailyQuotaMib,v=>profile.dailyQuotaMib=v,1000000000);
    numeric(grid,"profileMonthly",profile.monthlyQuotaMib,v=>profile.monthlyQuotaMib=v,1000000000);
    numeric(grid,"profileWarning",profile.warningPercent,v=>profile.warningPercent=v,100,1);
    domains(grid,"policyAllow",profile.allowDomains,v=>profile.allowDomains=v);
    domains(grid,"policyBlock",profile.blockDomains,v=>profile.blockDomains=v);
    domains(grid,"policyNoCache",profile.noCacheDomains,v=>profile.noCacheDomains=v);
    const scheduleContainer=document.createElement("div");card.append(scheduleContainer);
    for(const schedule of profile.schedules){
      activeOwner=schedule;
      const row=document.createElement("div");row.className="schedule-row";scheduleContainer.append(row);
      labelInput(row,"scheduleDays",schedule.days.join(","),raw=>{const days=raw.split(",").map(v=>Number(v.trim()));if(!days.length||days.some(v=>!Number.isInteger(v)||v<1||v>7)||new Set(days).size!==days.length)return false;schedule.days=days;return true;});
      const time=(m:number)=>`${String(Math.floor(m/60)).padStart(2,"0")}:${String(m%60).padStart(2,"0")}`;
      labelInput(row,"scheduleStart",time(schedule.startMinute),raw=>{const m=parseTime(raw);if(m===null)return false;schedule.startMinute=m;return m!==schedule.endMinute;},"time");
      labelInput(row,"scheduleEnd",time(schedule.endMinute),raw=>{const m=parseTime(raw);if(m===null)return false;schedule.endMinute=m;return m!==schedule.startMinute;},"time");
      const label=document.createElement("label");label.className="profile-field";label.textContent=t("scheduleAction");
      const select=document.createElement("select");for(const action of ["deny","limit"] as const)select.add(new Option(t(action==="deny"?"scheduleDeny":"scheduleLimit"),action));select.value=schedule.action;select.disabled=busy;select.addEventListener("change",()=>{schedule.action=select.value as ScheduleWindow["action"];changed();});label.append(select);row.append(label);
      numeric(row,"profileUpload",schedule.uploadBytesPerSecond/1024,v=>schedule.uploadBytesPerSecond=v*1024,976562);
      numeric(row,"profileDownload",schedule.downloadBytesPerSecond/1024,v=>schedule.downloadBytesPerSecond=v*1024,976562);
      button(row,"removeSchedule",()=>{profile.schedules.splice(profile.schedules.indexOf(schedule),1);changed();renderProfileEditors(container,profiles,t,changed,busy);});
    }
    const actions=document.createElement("div");actions.className="button-row";card.append(actions);
    button(actions,"addSchedule",()=>{profile.schedules.push({days:[1,2,3,4,5],startMinute:22*60,endMinute:7*60,action:"deny",uploadBytesPerSecond:0,downloadBytesPerSecond:0});changed();renderProfileEditors(container,profiles,t,changed,busy);});
    button(actions,"removeProfile",()=>{profiles.splice(profiles.indexOf(profile),1);changed();renderProfileEditors(container,profiles,t,changed,busy);});
    const id=document.createElement("small");id.className="field-help";id.textContent=`ID: ${profile.id}`;card.append(id);
    container.append(card);
  }
}
