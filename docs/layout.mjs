// Interchange calibration from tarkov.dev / Map Companion maps.json (MIT).
export const layout={a:.265,b:150.6,c:.265,d:134.6,r:Math.PI, bounds:[[598,-442],[-433,426]],tile:'https://assets.tarkov.dev/maps/interchange/main',svg:'https://assets.tarkov.dev/maps/svg/Interchange.svg',author:'Shebuka'};
export function project(x,z){let rx=x*Math.cos(layout.r)-z*Math.sin(layout.r),ry=x*Math.sin(layout.r)+z*Math.cos(layout.r);return [layout.a*rx+layout.b,-layout.c*ry+layout.d]}
export function unproject(px,py){let rx=(px-layout.b)/layout.a,ry=(layout.d-py)/layout.c;return [rx*Math.cos(layout.r)+ry*Math.sin(layout.r),-rx*Math.sin(layout.r)+ry*Math.cos(layout.r)]}
export const corners=layout.bounds.map(([x,z])=>project(x,z));
export const bounds=[Math.min(corners[0][0],corners[1][0]),Math.min(corners[0][1],corners[1][1]),Math.abs(corners[0][0]-corners[1][0]),Math.abs(corners[0][1]-corners[1][1])];
export function guidance(p,t){const dx=t.x-p.x,dz=t.z-p.z;let bearing=(Math.atan2(dx,dz)*180/Math.PI+360)%360;let turn=((bearing-p.yaw+540)%360)-180;return {distance:Math.hypot(dx,dz),turn};}

// Floor footprints and heights from tarkov.dev's Interchange catalog.
export function floorFor(p){const inside=p.x>=-222&&p.x<=120&&p.z>=-327&&p.z<=218;return inside&&p.y>=34?'Second_Floor':inside&&p.y>=25?'First_Floor':'Ground_Level';}
export const labels=[{name:'Power Station',x:-186.4,z:-318.7,floor:'Ground_Level'},{name:'Scav Camp',x:263.2,z:-11.1,floor:'Ground_Level'},{name:'Garage A',x:33,z:-222,floor:'Ground_Level'},{name:'Garage B',x:47,z:-112,floor:'Ground_Level'},{name:'Garage C',x:0,z:47,floor:'Ground_Level'},{name:'Garage D',x:20,z:138,floor:'Ground_Level'},{name:'IDEA',x:-34,z:-235,floor:'First_Floor'},{name:'Goshan',x:-115,z:-45,floor:'First_Floor'},{name:'OLI',x:-28,z:140,floor:'First_Floor'},{name:'Kiba',x:-18,z:-25,floor:'First_Floor'},{name:'Techlight',x:91,z:54,floor:'Second_Floor'}];

// Zone labels are upstream reference points, not surveyed boundaries.
export function zoneFor(p){
  if(!p || ![p.x,p.y,p.z].every(Number.isFinite)) return {name:'Non disponibile',estimated:false};
  const [px,py]=project(p.x,p.z);
  if(px<bounds[0]||px>bounds[0]+bounds[2]||py<bounds[1]||py>bounds[1]+bounds[3]) return {name:'Fuori area',estimated:false};
  const floor=floorFor(p);
  const inside=p.x>=-222&&p.x<=120&&p.z>=-327&&p.z<=218;
  let candidates=labels.filter(l=>l.floor===floor);
  let fallback=floor==='First_Floor'?'Centro commerciale':floor==='Second_Floor'?'Piano superiore':'Esterno / parcheggio';
  if(floor==='Ground_Level') {
    candidates=candidates.filter(l=>inside||!l.name.startsWith('Garage '));
  }
  const nearest=candidates.map(l=>({name:l.name,distance:Math.hypot(l.x-p.x,l.z-p.z)})).sort((a,b)=>a.distance-b.distance)[0];
  const limit=floor==='Ground_Level'?(inside?65:75):floor==='First_Floor'?65:35;
  return nearest&&nearest.distance<=limit?{name:nearest.name,estimated:true}:{name:fallback,estimated:false};
}
export function centeredView(view,p){const [x,y]=project(p.x,p.z);return [x-view[2]/2,y-view[3]/2,view[2],view[3]];}
