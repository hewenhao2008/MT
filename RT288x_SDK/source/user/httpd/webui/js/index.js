var oConf = {};

$(document).ready(function() {
	initData();
	initEvents();
});

function fixupInitVals() {
	$('#ap_standalone').val("0");
}

function initData() {
	$.get('conf.cgi', function(d, s, xhr) {
		oConf = nv2json(d);
		//赋值
		jsonTraversal(oConf, jsTravSet);

		//修正初始值
		fixupInitVals();

		//init status
		OnLanDhcpChanged();

		//others
		window.document.title = oConf['os_version']
	});
}

function OnConfSave() {
	//取值
	jsonTraversal(oConf, jsTravGet);
	var conf = a2str(oConf);
	$.post('post.cgi', conf, function(d, s, x) {
		//console.log(d);
		OnSysServices();
		window.location.reload();
	});
}

function OnLanDhcpChanged() {
	var dhcp = $('#lan_dhcp').val();
	if (dhcp == '1') {
		$("#lan_ipaddr").attr('disabled', true);
		$("#lan_netmask").attr('disabled', true);
		$("#lan_gateway").attr('disabled', true);
	} else {
		$("#lan_ipaddr").attr('disabled', false);
		$("#lan_netmask").attr('disabled', false);
		$("#lan_gateway").attr('disabled', false);
	}
}

function OnSysReset() {
	$.post('exec.cgi', "kill -USR2 `pidof nvram_daemon`", function(d, s, x) {
		//console.log(d);
		window.location.reload();
	});
}

function OnSysRestart() {
	$.post('exec.cgi', "reboot", function(d, s, x) {
		//console.log(d);
		window.location.reload();
	});
}

function OnSysUpdate() {
	$.post('exec.cgi', "online_upgrade.sh", function(d, s, x) {
		//console.log(d);
		window.location.reload();
	});
}

function OnSysServices() {
	$.post('exec.cgi', "ugw_services.sh restart", function(d, s, x) {
		//console.log(d);
		window.location.reload();
	});
}

function OnCloudAccountChg() {
	var accout = $('#cloud_account').val();
	if (accout != "") {
		//setup default cloud addr
		$("#ac_ipaddr").val($('#ac_ipaddr_def').val());
	} else {
		$("#ac_ipaddr").val('');
	}
}

function initEvents() {
	$('#btn_save_conf').on('click', OnConfSave);
	$('#btn_sys_reset').on('click', OnSysReset);
	$('#btn_sys_restart').on('click', OnSysRestart);
	// $('#btn_sys_service').on('click', OnSysServices);
	$('#btn_sys_update').on('click', OnSysUpdate);
	$('#lan_dhcp').on('change', OnLanDhcpChanged);
	$('#cloud_account').on('change', OnCloudAccountChg);
}