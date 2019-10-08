var d = document;
var od = d.createElement('div');
od.style.cssText = "position: fixed; top: 0; display: block; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); z-index: 999;"
var dd = d.createElement('div');
dd.style.cssText = "position: absolute; top: 45%; left: 45%;";
var i = d.createElement('textarea');
i.placeholder = "Paste data uri here...";
var s = d.createElement('button');
s.innerHTML = "Download File/Close";
s.addEventListener("click", function() {
if (i.value == "") { 
d.body.removeChild(od);
return; }
l = d.createElement('a');
l.download = "configs.zip";
l.href = i.value;
l.click();
dd.appendChild(l);
l.click();
d.body.removeChild(od);
});
dd.appendChild(i);
dd.appendChild(d.createElement('br'));
dd.appendChild(s);
od.appendChild(dd);
d.body.appendChild(od);
