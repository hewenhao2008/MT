/*
 *
 */
! function(root) {
	//其它导出函数
	function recurseTravSubNode(o, parent, full_path, cb_leaf_node, prefix) {
		//递归函数,遍历素有字节点.
		var oset = o;
		for (var k in o) {
			var fp = full_path + '__' + k;
			if (typeof(o[k]) == 'object') {
				//还有子节点.
				oset[k] = recurseTravSubNode(o[k], k, fp, cb_leaf_node, prefix);
			} else {
				//最后一级
				if (typeof(prefix) == 'string') {
					fp = prefix + '__' + fp;
				};
				oset[k] = cb_leaf_node(fp, k, o[k], prefix);
			}
		}
		return oset;
	}

	/*
    遍历对象, 
    执行回调 cb_leaf_node(full_path, key, value){ return new_value;}, 
    返回路径: 
    {
        "Addr": {
           "Ip": "200.200.0.13",
           "Mask": "255.255.255.255"
        },
        "Enable": "true",
        "Gw": "wan0",
        "Name": "static",
        "Via": "200.200.20.1"
    }
    返回: 新node, 可通过回调返回值来 改写节点里面的值.
    */
	function jsonTraversal(o, cb_leaf_node, prefix) {
		//root
		var oset = o;
		for (var k in o) {
			if (typeof(o[k]) == 'object') {
				oset[k] = recurseTravSubNode(o[k], k, k, cb_leaf_node, prefix);
			} else {
				//final
				var fp = k;
				if (typeof(prefix) == 'string') {
					fp = prefix + '__' + k;
				};
				oset[k] = cb_leaf_node(fp, k, o[k], prefix);
			}
		}
		return oset;
	}

	function getControlByIdMisc(id) {
		//优先尝试input类型,其次select,再次ID.
		var id = id.replace(/[\/\:\.\$]/g, '_');
		var res = $('input#' + id);
		if (res.length < 1) {
			res = $('select#' + id);
		}
		if (res.length < 1) {
			res = $('#' + id);
		};
		return res;
	}

	/*
    需要特殊处理的控件:
    checkbox, radio
    不需要特殊处理的:
    text, texterea, select,
    */
	function jsTravSet(fp, k, v) {
		var j = getControlByIdMisc(fp);
		var t = j.attr('type');
		switch (t) {
			case "checkbox":
				if (typeof(v) == 'boolean') {
					j.attr('checked', v);
				} else if (typeof(v) == 'string') {
					j.attr('checked', (v == j.val() ? true : false));
				}
				break;
			case "radio":
				$('input:radio[name="' + fp + '"]').each(function() {
					if ($(this).val() == v) {
						$(this).attr('checked', true);
					} else {
						$(this).attr('checked', false);
					}
				});
				break;
			default:
				j.val(v);
				break;
		}

		return v;
	}

	function jsTravGet(fp, k, v) {
		var j = getControlByIdMisc(fp);
		var t = j.attr('type');
		var nv;
		switch (t) {
			case 'checkbox':
				if (typeof(v) == 'boolean') {
					nv = (j.attr('checked') == 'checked' ? true : false);
				} else if (typeof(v) == 'string') {
					nv = (j.attr('checked') == 'checked' ? j.val() : "");
				};
				break;
			case 'radio':
				nv = $('input:radio[name="' + fp + '"]:checked').val();
				break;
			default:
				nv = j.val();
				break;
		}

		nv = (nv == undefined ? v : nv);
		//convert type
		if (typeof(v) == 'number') {
			nv = parseInt(nv);
		};
		return nv;
	}

	function nv2json(nvs, append) {
		var reo = {};
		var aNvs = nvs.split('\n');
		for (var i = aNvs.length - 1; i >= 0; i--) {
			var line = aNvs[i];
			if (line.length < 3) {
				continue;
			}
			var nvkv = line.split('=');
			if (nvkv.length >= 2) {
				reo[nvkv[0]] = nvkv[1];
			} else {
				reo[nvkv[0]] = ""
			}
		};

		if (append != undefined) {
			for (var k in append) {
				if (reo[k] == undefined) {
					reo[k] = append[k];
				}
			}
		}

		return reo;
	}

	function a2str(o, filter) {
		var str = '';

		for (var k in o) {
			if (k.length > 0 && o[k] != undefined) {
				//filter
				if (filter && !filter(k)) {
					continue;
				}
				//comb
				if (str.length > 0)
					str += '&';
				str += k + '=' + o[k];
			}
		}

		return str;
	}

	function trimv(v) {
		return v.split('\n')[0];
	}

	//utils
	function trim_string(str) {
		var trim = str + "";
		trim = trim.replace(/^\s*/, "");
		return trim.replace(/\s*$/, "");
	}

	function is_char_valid(str) {
		for (var i = 0; i < str.length; i++) {
			if ((str.charAt(i) >= '0' && str.charAt(i) <= '9') ||
				(str.charAt(i) >= 'a' && str.charAt(i) <= 'z') || (str.charAt(i) >= 'A' && str.charAt(i) <= 'Z') ||
				(str.charAt(i) == '-') || (str.charAt(i) == '_') || (str.charAt(i) == '.'))
				continue;

			return false;
		}
		return true;
	}

	function is_number_valid(value) {
		var value = value + "";
		return value.match(/^-?\d*\.?\d+$/) ? true : false;
	}

	function is_number_range(value, min, max) {
		return (is_number_valid(value) && value >= min && value <= max);
	}

	function is_number_range2(value, min) {
		return (is_number_valid(value) && value >= min);
	}

	function is_port_valid(port) {
		return (is_number_valid(port) && port >= 1 && port <= 65535);
	}

	function bigger_port_than(port1, port2) {
		return ((port1 - 0) < (port2 - 0));
	}

	function is_empty(value) {
		var str = value + " ";
		return str.match(/^\s*$/) ? false : true;
	}

	function is_blank(value) {
		var str = value + " ";
		return str.match(/^\s*$/) ? false : true;
	}

	function is_hex_valid(hex) {
		var hex = hex + "";
		var got = hex.match(/^[0-9a-fA-F]{1,}$/);
		if (!got) {
			return false;
		}
		return true;
	}

	function is_mac_valid(macaddr) {
		var mac = macaddr + "";
		var got = mac.match(/^[0-9a-fA-F]{2}[:-]?[0-9a-fA-F]{2}[:-]?[0-9a-fA-F]{2}[:-]?[0-9a-fA-F]{2}[:-]?[0-9a-fA-F]{2}[:-]?[0-9a-fA-F]{2}$/);
		if (!got) {
			return false;
		}

		mac = mac.replace(/[:-]/g, '');
		if (mac.match(/^0{12}$/) || mac.match(/^[fF]{12}$/)) {
			return false;
		}

		return true;
	}

	function ipv4_to_bytearray(ipaddr) {
		var ip = ipaddr + "";
		var got = ip.match(/^\s*(\d{1,3})\s*[.]\s*(\d{1,3})\s*[.]\s*(\d{1,3})\s*[.]\s*(\d{1,3})\s*$/);
		if (!got) {
			return 0;
		}
		var a = [];
		var q = 0,
			p = 0;
		for (var i = 1; i <= 4; i++) {
			q = parseInt(got[i], 10);
			p = parseInt(got[4], 10);
			if (q < 0 || q > 255 || p == 0 || p == 255) {
				return 0;
			}
			a[i - 1] = q;
		}
		return a;
	}

	function is_ipv4_valid(ipaddr) {
		if (ipaddr == "0.0.0.0" || ipaddr == "127.0.0.1")
			return false;

		var ip = ipv4_to_bytearray(ipaddr);
		if (ip == 0)
			return false;

		return true;
	}

	function is_ipv4_subnet(ipaddr_1, mask, ipaddr_2) {
		var mn = mask.split(".");
		var ip1 = ipaddr_1.split(".");
		var ip2 = ipaddr_2.split(".");
		if (ip1.length != 4 || ip2.length != 4 || mn.length != 4)
			return false;

		for (var k = 0; k <= 3; k++) {
			if ((ip1[k] & mn[k]) != (ip2[k] & mn[k]))
				return false;
		}
		return true;
	}

	function is_ipv4_range(ipaddr_1, ipaddr_2) {
		var ip1 = ipaddr_1.split(".");
		var ip2 = ipaddr_2.split(".");
		if (ip1.length != 4 || ip2.length != 4)
			return false;

		for (var k = 0; k < 4; k++) {
			var a = Number(ip1[3]);
			var b = Number(ip2[3]);
			if (a >= b)
				return false;
		}
		return true;
	}

	function is_ipv4_range2(ipaddr_1, ipaddr_2) {
		var ip1 = ipaddr_1.split(".");
		var ip2 = ipaddr_2.split(".");
		if (ip1.length != 4 || ip2.length != 4)
			return false;

		for (var k = 0; k < 4; k++) {
			var a = Number(ip1[3]);
			var b = Number(ip2[3]);
			if (a > b)
				return false;
		}
		return true;
	}

	function mask4_to_bytearray(mask) {
		var mn = mask + "";
		var got = mn.match(/^\s*(\d{1,3})\s*[.]\s*(\d{1,3})\s*[.]\s*(\d{1,3})\s*[.]\s*(\d{1,3})\s*$/);
		if (!got) {
			return 0;
		}
		var a = [];
		var q = 0,
			p = 0;
		for (var i = 1; i <= 4; i++) {
			q = parseInt(got[i], 10);
			p = parseInt(got[4], 10);
			if (q < 0 || q > 255) {
				return 0;
			}
			a[i - 1] = q;
		}
		return a;
	}

	function is_mask4_valid(mask) {
		var mask = mask4_to_bytearray(mask);
		if (mask == 0)
			return false;

		return true;
	}

	function is_serverip_valid(str) {
		if (is_ipv4_valid(str)) {
			if (!is_char_valid(str))
				return false;
		}

		return true;
	}

	function checkDate(str) {
		var month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
		var week = [MM_sun, MM_mon, MM_tue, MM_wed, MM_thu, MM_fri, MM_sat];

		if ((str.substring(4, 5)) == " ") str = str.replace(" ", "");
		else str = str;

		var t = str.split(" ");
		for (var j = 0; j < 12; j++) {
			if (t[0] == month[j]) t[0] = j + 1;
		}
		return t[2] + "-" + t[0] + "-" + t[1];
	}

	function checkNTPDate(str) {
		var month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
		var week = [MM_sun, MM_mon, MM_tue, MM_wed, MM_thu, MM_fri, MM_sat];
		var s1;
		var s2;
		if ((str.substring(8, 9)) == " ") {
			s1 = str.substring(0, 8);
			s2 = str.substring(9, str.length);
			str = s1.concat(s2);
		} else {
			str = str;
		}

		var t = str.split(" ");
		for (var j = 0; j < 12; j++) {
			if (t[1] == month[j]) t[1] = j + 1;
		}

		return t[5] + "-" + t[1] + "-" + t[2] + " " + t[3];
	}

	function fmtFlow(v) {
		var iv = parseInt(v);
		if (iv > (1024 * 1024)) {
			//Mb
			return Math.round(iv / 1024 / 1024) + ' MB/s';
		}
		if (iv > (1024)) {
			return Math.round(iv / 1024) + ' KB/s';
		}
		return iv + ' Bytes/s';
	}

	//遍历赋值
	root.jsTravGet = jsTravGet;
	root.jsTravSet = jsTravSet;
	root.jsonTraversal = jsonTraversal;

	root.nv2json = nv2json;
	root.a2str = a2str;
	root.trimv = trimv;

	root.fmtFlow = fmtFlow;

}(this);