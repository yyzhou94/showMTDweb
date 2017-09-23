
$.ajaxSetup({ cache: false })
var url = "http://" + location.hostname + ":8080";

function updatePortStats() {

    var statsTableBody = document.getElementById('port-stats-data');
    console.log(statsTableBody)
    while (statsTableBody.firstChild) {
            statsTableBody.removeChild(statsTableBody.firstChild);
    }
    console.log(statsTableBody)
    console.log('updateFLowStats #######################')

    $.getJSON(url.concat("/stats/switches"), function(switches){
        $.each(switches, function(index, dpid){
            // console.log(dpid);
            var hex_dpid = parseInt(dpid).toString(16);

            $.getJSON(url.concat("/stats/port/").concat(dpid), function(ports) {
                var portStats = ports[dpid];
                portStats.sort(function (a,b) {return a.port_no >= b.port_no ? 1 : -1})

                var tr = document.createElement('TR');
                var physicalPorts = 0;
                var switchColTd = document.createElement('TD');
                switchColTd.appendChild(document.createTextNode(hex_dpid));
                tr.appendChild(switchColTd);

                $.each(portStats, function(index, obj) {
                    if (obj.port_no < 65280) {
                        // console.log(obj);
                        physicalPorts += 1;
                        // var statsArray = new Array(obj.port_no, obj.rx_packets, obj.rx_bytes, obj.rx_dropped, obj.rx_errors, obj.tx_packets, obj.tx_bytes, obj.tx_dropped, obj.tx_errors);
                        var statsArray = new Array(obj.port_no, obj.rx_packets, obj.rx_bytes, obj.rx_dropped, obj.rx_errors);

                        $.each(statsArray, function(index, value) {
                            var td = document.createElement('TD');
                            td.appendChild(document.createTextNode(value));
                            tr.appendChild(td);
                        });
                        statsTableBody.appendChild(tr);
                        tr = document.createElement('TR');
                    }
                });

                switchColTd.rowSpan = physicalPorts;
            });
        });
    });
    console.log(statsTableBody)
}

updatePortStats();

var portStatsIntervalID = setInterval(function(){updatePortStats()}, 5000);

function stopPortStatsTableRefresh() {
    clearInterval(portStatsIntervalID);
}
