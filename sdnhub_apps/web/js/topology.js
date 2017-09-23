 

var switchList = {};
var hostList = {};
// var hostSwitchLinkList = [];

var url = "http://" + location.hostname + ":8080";
var graph = new joint.dia.Graph;
var erd = joint.shapes.erd;

var element = function(elm, x, y, label) {
    var cell = new elm({ position: { x: x, y: y }, size: { width: 125, height: 35 },
	      attrs: { text: { text: label }}});

	cell.attr({
		  rect: { fill: '#2C3E50', rx: 5, ry: 5, 'stroke-width': 2, stroke: 'black' },
	      text: {
	          fill: 'white',
	          'font-size': 16, 'font-weight': 'bold', 'font-variant': 'small-caps', 'text-transform': 'capitalize'
	      }
	  });

    graph.addCell(cell);
    return cell;
};

var link = function(elm1, elm2) {
    var cell = new erd.Line({ source: { id: elm1.id }, target: { id: elm2.id },
        attrs : { '.connection': { stroke: 'blue' } },
        labels: [{ text: {'font-size': 30 } },
                 { text: {'font-size': 50 } }]
    });

    graph.addCell(cell);
    return cell;
};

var getSwitchDesc = function(dpid) {
    var ofctl_dpid = parseInt(dpid, 16);
    $.getJSON(url.concat("/stats/desc/").concat(ofctl_dpid), function(descs){
	    $.each(descs, function(key, value){
            var valueJson = JSON.stringify(value);
            var switchDesc = JSON.parse(valueJson);
            switchList[dpid]['desc'] = switchDesc;
        });
    }).then(setSwitchTooltip);
};

var getDom = function(modelId) {
    var elems = document.getElementsByClassName("element");
    for (i=0;i < elems.length; i++) {
        dom = document.getElementById(elems[i].id);
        if (modelId == dom.getAttribute("model-id"))
            return dom;
    }
    return undefined;
};

var setSwitchTooltip = function() {
    $.each(switchList, function(dpid, value) {
        var rectDom = getDom(value.element.id);
        if (rectDom != undefined && value.desc != undefined) {
            value['tooltip'] = new joint.ui.Tooltip({
                    target: rectDom,
                    content: '<span>Switch ' + value['name'] + '</span>' +
                             '<hr><table>' +
                             '<tr><td>类型:</td><td>' + value.desc.hw_desc + '</td></tr>' +
                             '<tr><td>交换机版本:</td><td>' + value.desc.sw_desc + '</td></tr>' +
                             // '<tr><td>Vendor:</td><td>' + value.desc.mfr_desc + '</td></tr>' +
                             // '<tr><td>Serial #:</td><td>' + value.desc.serial_num + '</td></tr>' +
                             '<tr><td>描述:</td><td>' + value.desc.dp_desc + '</td></tr>' +
                             '</table>',
                    top: rectDom,
                    direction: 'top'
            });
        }
    });
};

var hostCleanup = function(currentHosts) {
    $.each(hostList, function(key, value){
        if (value.tooltip){
            value.tooltip.remove();
        }
        if (value.link){
            value.link.remove();
        }

        if (!(key in currentHosts))
            value.element.remove();
    });
};

var drawHosts = function() {
	srcSwitch = {};
	dstSwitch = {};


$.getJSON(url.concat("/v1.0/topology/hosts"), function(hosts){
        //Remove old tooltips and host links
        // alert(hosts[0])
        hostCleanup(hosts);

        $.each(hosts, function(key, value){
            //Do all common stuff for an IP
            var valueJson = JSON.stringify(value);
            var obj = JSON.parse(valueJson);
            // console.log(hosts)
            if (!(key in hostList))
                hostList[key] = {};

            if (!('element' in hostList[key])) {
                var x = 1000, y=1000;
                var cell = new erd.Normal({ position: { x: x, y: y }, attrs: { text: { text: key }}});
                graph.addCell(cell);

                hostList[key]['element'] = cell;
                hostList[key]['dom'] = getDom(cell.id);
            }

            hostList[key]['entry'] = obj;
            var hostDom = hostList[key]['dom'];
            var cell = hostList[key]['element'];

            if (obj.port.dpid in switchList && hostDom != undefined) {
                // console.log('i\'m in this ')
                var date = new Date();
                var dateStr = (date.getMonth() + 1) + "/" +
                               date.getDate() + "/" +
                               date.getFullYear() + " " +
                               date.getHours() + ":" +
                               date.getMinutes() + ":" +
                               date.getSeconds();

                hostList[key]['tooltip'] = new joint.ui.Tooltip({
                        target: hostDom,
                        content:
                                 '<table>' +
                                 '<tr><td>MAC:</td><td>' + obj.mac + '</td></tr>' +
                                 '<tr><td>连接的交换机:</td><td>' + '交换机'+parseInt(obj.port.dpid) + '</td></tr>' +
                                 '<tr><td>连接的端口:</td><td>' + parseInt(obj.port.port_no) + '</td></tr>' +
                                 '<tr><td>时间:</td><td>' + dateStr + '</td></tr>' +
                                 '</table>',
                        top: hostDom,
                        direction: 'top'
                });
                // console.log(switchList[obj.port.dpid]);
                hostList[key]['link'] =link(switchList[obj.port.dpid]['element'], cell);
                // link(switchList[obj.dpid]['element'], cell)
            }
        });
        joint.layout.DirectedGraph.layout(graph, { setLinkVertices: false, edgeSep: 20, rankSep: 80, nodeSep: 2 });
    });
};

var drawLinks = function() {
	srcSwitch = {};
	dstSwitch = {};
	$.getJSON(url.concat("/v1.0/topology/links"), function(links){
	    $.each(links, function(key, value){
            var valueJson = JSON.stringify(value);
            var obj = JSON.parse(valueJson);

            var portname = obj.src.name;
            link(switchList[obj.src.dpid]['element'],
                 switchList[obj.dst.dpid]['element']).cardinality(portname);
		});
        joint.layout.DirectedGraph.layout(graph, { setLinkVertices: false, edgeSep: 20, rankSep: 80, nodeSep: 10 });
	}).then(drawHosts);
}

$(function()  {
    var paperScroller = new joint.ui.PaperScroller;

    var paper = new joint.dia.Paper({
            el: paperScroller.el,
            width: 3600,
            height: 2400,
            model: graph
    });

    paperScroller.options.paper = paper;
    $('#paper-container').append(paperScroller.render().el);
    paper.on('blank:pointerdown', paperScroller.startPanning);
    paperScroller.center();

$.getJSON(url.concat("/v1.0/topology/switches"), function(switches){
	// var counter = 0;
    var num = 1;
    $.each(switches, function(index, value){
		var valueJson = JSON.stringify(value);
        var obj = JSON.parse(valueJson);

        switchList[obj.dpid] = {};
        if (obj.dpid[0] != '0'){
            var switchName = '物理SDN交换机' + num;
            num = num+1;
        }
        else{
            var switchName = '虚拟SDN交换机' + parseInt(obj.dpid);
        }



        // var switchName = obj.dpid;
        switchList[obj.dpid]['name'] = switchName;

        var x = 200 + 150 * (index%4);
        var y = 100 + 150 * Math.floor(index/4);
		switchList[obj.dpid]['element'] = element(joint.shapes.basic.Rect, x, y, switchName);

        getSwitchDesc(obj.dpid);

    });
}).then(drawLinks);

paper.on('cell:pointerdown',
    function(cellView, evt, x, y) {
        $.each(switchList, function(key, value) {
          if (value.id == cellView.model.id) {
            console.log("Clicked " + key);
          }
        });
});

});
var drawHostIntervalD = setInterval(function(){drawHosts()}, 1000000);
function stopDrawHostRefresh() {
    clearInterval(drawHostIntervalD);
}
//
graph.on('change:position', function(cell) {
    var parentId = cell.get('parent');
    if (!parentId) return;

    var parent = graph.getCell(parentId);
    var parentBbox = parent.getBBox();
    var cellBbox = cell.getBBox();

    if (parentBbox.containsPoint(cellBbox.origin()) &&
        parentBbox.containsPoint(cellBbox.topRight()) &&
        parentBbox.containsPoint(cellBbox.corner()) &&
        parentBbox.containsPoint(cellBbox.bottomLeft())) {

        // All the four corners of the child are inside
        // the parent area.
        return;
    }

    // Revert the child position.
    cell.set('position', cell.previous('position'));
});
