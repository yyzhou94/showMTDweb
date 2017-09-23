var url = "http://" + location.hostname + ":8080";


function turnOn1_1(){
  alert('主机发现MTD启动')
  $.post(url.concat("/v1.0/scan/host_mtd"),function(){
  },"json")
}


function turnOn1_2(){
  alert('主机发现MTD关闭')
  $.post(url.concat("/v1.0/scan/stop_host_mtd"),function(){
  },"json")
}

function turnOn2_1(){
  alert('端口扫描MTD启动')
  $.post(url.concat("/v1.0/scan/port_mtd"),function(){
  },"json")
}
function turnOn2_2(){
  alert('端口扫描MTD关闭')
  $.post(url.concat("/v1.0/scan/stop_port_mtd"),function(){
  },"json")
}


function turnOn3_1(){
  alert('拓扑映射MTD启动')
  $.post(url.concat("/v1.0/disco/topo_mtd"),function(){
  },"json")
}
function turnOn3_2(){
  alert('拓扑映射MTD关闭')
  $.post(url.concat("/v1.0/disco/stop_topo_mtd"),function(){
  },"json")
}

function reset(){
    for (var i=1;i < 6;i++){
        var s  = pre+i.toString();
        var a = sessionStorage.getItem(s);
        if (a == '1'){
            var st = "#switch-onColor"+i.toString();
            $(st).bootstrapSwitch('state',false,false);
        }
    }
    $.post(url.concat("/v1.0/reset"),function(){
    },"json")
}



