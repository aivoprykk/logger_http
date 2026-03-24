(function (win) {
    var baseuri = '';
    if (process.env.NODE_ENV === 'development') {
        baseuri = 'http://10.10.10.1';
    }
    win.app = {
        curobj: null,
        init: function () {
            this.snackbar.init();
            window.app.fw.init();
            window.app.files.init();
            window.app.config.init();
            window.app.home.init();
            window.app.fileupload.init();
            var d = document.createElement('dialog');
            d.innerHTML = '<article><h3>Confirm your action!</h3><p class="msg"></p><footer><button class="secondary outline cancel" href="#cancel" role="button">Cancel</button><button class="outline ok" href="#confirm" role="button">Proceed</button><footer></article>';
            document.body.appendChild(d);
            var closebtn = document.querySelector('dialog .cancel');
            if (d) {
                closebtn.addEventListener('click', function () {
                    d.close();
                    return false;
                });
            }
            var el = document.querySelector('nav .brand');
            var a = document.createElement('span');
            a.className = 'sm';
            a.innerHTML = 'GPS';
            el.appendChild(a);
            a = document.querySelectorAll('header nav li .restart');
            if (a) {
                a.forEach(function (el) {
                    el.addEventListener('click', function (e) {
                        win.app.dlg(function() {
                            var cb = function (resp) {
                                if (!resp) {
                                    win.app.snackbar.show('System restarting...');
                                }
                                win.app.snackbar.show('Restart command failed.');
                            };
                            win.app.load('/api/v1/system/restart', 'text', cb.bind(self));
                            return false;
                        }, 'Reboot?');
                        e.preventDefault();
                    });
                });
            }
        },
        mkmenuactive: function (cl) {
            var i, j;
            var a = document.querySelectorAll('header nav li');
            for (i = 0, j = a.length; i < j; i++) {
                if (a[i].classList.contains(cl)) {
                    a[i].classList.add('active');
                } else {
                    a[i].classList.remove('active');
                }
            }
        },
        size: function (size) {
            var i = size, j = 0;
            while (i > 1024) {
                i = i / 1024;
                ++j;
            }
            i = Math.round(i * 100) / 100;
            return i + ' ' + (j === 0 ? 'b' : j === 1 ? 'K' : j === 2 ? 'M' : 'G');
        },
        showsvg: function (node, data, color, w, h) {
            const iconSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
            const iconPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
            iconSvg.setAttribute('fill', color || '#1f1f1f');
            iconSvg.setAttribute('viewBox', '0 -960 960 960');
            iconSvg.setAttribute('width', (w || '24') + 'px');
            iconSvg.setAttribute('height', (h || '24') + 'px');
            iconSvg.setAttribute('stroke', '#fff');
            iconSvg.classList.add('my-icon');
            iconPath.setAttribute('d', data);
            iconSvg.appendChild(iconPath);
            return node.appendChild(iconSvg);
        },
        load: function (url, type, callback, data) {
            var xhr = new XMLHttpRequest(), d = '';
            xhr.responseType = type;
            xhr.onreadystatechange = () => {
                if (xhr.readyState === 4)  callback(xhr.response);
            };
            xhr.open(data ? 'POST' : 'GET', baseuri + url, true);
            if (data && type === 'json') {
                xhr.setRequestHeader('Content-Type', 'application/json');
                if (data && typeof data === 'object') d = JSON.stringify(data);
                else d = data;
            }
            xhr.send(d);
        },
        sort: function (property, order) {
            if (property[0] === '-') {
                property = property.substr(1);
            }
            return function (a, b) {
                var c = +a[property], d = +b[property], result;
                if (!isNaN(c) && !isNaN(d)) result = (c < d) ? -1 : (c > d) ? 1 : 0;
                else result = (a[property] < b[property]) ? -1 : (a[property] > b[property]) ? 1 : 0;
                return result * order;
            };
        },
        fileupload: {
            el: null,
            files: [],
            changeevent: function (event) {
                win.app.fileupload.fileselected(event);
            },
            init: function () {
                var self = win.app.fileupload;
                var obj = document.querySelector('main .upload-file');
                var i; var j;
                if (obj) {
                    i = self.el = obj.querySelector('input[type=file]');
                    j = obj.querySelector('.upload-submit');
                }
                if (i) {
                    self.changel = i.addEventListener('change', self.changeevent, false);
                }
                if (j) {
                    j.innerHTML = '';
                    win.app.showsvg(j, 'M440-320v-326L336-542l-56-58 200-200 200 200-56 58-104-104v326h-80ZM240-160q-33 0-56.5-23.5T160-240v-120h80v120h480v-120h80v120q0 33-23.5 56.5T720-160H240Z', 'var(--pico-primary)', 24, 24);
                    j.addEventListener('click', function (e) {
                        win.app.curobj.upload(e);
                    });
                    j.setAttribute('disabled', 'true');
                }
            },
            upload: function (url, callback) {
                var self = win.app.fileupload;
                var file = self.el, size = 0;
                if (file && file.files && file.files.length > 0) {
                    var data = new FormData();
                    data.append('file', file.files[0]);
                    size = file.files[0].size;
                } else {
                    if (file)
                        console.log('Please select a file first.');
                    else
                        console.log('File input missing.');
                    return;
                }
                var txt = document.querySelector('.upload-file .upload-submit');
                if (txt) {
                    txt.setAttribute('disabled', 'true');
                }
                txt = file.parentNode.querySelector('.file-text');
                var textupdate = function (msg) {
                    if (txt) {
                        txt.innerHTML = msg;
                    }
                };
                self.el.removeEventListener('change', self.changeevent, true);
                var xhr = new XMLHttpRequest();
                xhr.onreadystatechange = function () {
                    if (xhr.readyState == 4) {
                        if (self.el) {
                            self.el.value = '';
                        }
                        if (xhr.status == 200) {
                            textupdate('Uploaded!');
                            win.app.snackbar.show('Success');
                            self.filedone('Upload file', false);
                            if (callback) {
                                callback(xhr.response);
                            }
                        }
                        else {
                            win.app.snackbar.show('Upload failed.');
                            self.filedone('Upload failed.', false);
                        }
                    }
                };
                xhr.upload.onprogress = function (e) {
                    if (e.lengthComputable) {
                        if (e.loaded < size) {
                            var percent = Math.ceil(e.loaded / size * 100);
                            textupdate('Uploading... ' + percent + '%');
                        }
                        else if (e.loaded >= size) {
                            textupdate('Uploading... 100%');
                        }
                    }
                };
                xhr.open('post', baseuri + url, true);
                xhr.timeout = 45000;
                xhr.send(data);
            },
            fileselected: function (event) {
                var self = win.app.fileupload, file = self.el;
                if (file && file.files && file.files.length > 0) {
                    var obj = file.files[0];
                    var name = obj.name;
                    var fileName = name.split('\\|/');
                    self.filedone('Selected ' + fileName[fileName.length - 1] + ' (' + win.app.size(obj.size) + ')', true);
                    var txt = document.querySelector('.upload-file .upload-submit');
                    if (txt) {
                        txt.removeAttribute('disabled');
                    }
                    event.preventDefault();
                }
            },
            filedone: function (msg, display) {
                var txt = document.querySelector('.file-text');
                if (txt) {
                    txt.innerHTML = msg;
                    txt = document.querySelector('.upload-file .upload-submit');
                    if (txt) {
                        txt.setAttribute('disabled', 'true');
                        if (display) txt.classList.remove('hide');
                        else txt.classList.add('hide');
                    }
                }
            }
        },
        snackbar: {
            init: function () {
                var self = win.app.snackbar;
                self.el = document.createElement('div');
                if (self.el) {
                    self.el.className = ('snackbar');
                    self.el.innerHTML = '<div class="snackbar-inner"><div class="msg"></div><div class="close">×</div></div>';
                    document.body.appendChild(self.el);
                    var x = self.el.querySelector('.close');
                    if (x) {
                        x.addEventListener('click', function () {
                            self.hide();
                        });
                    }
                }
            },
            show: function (msg) {
                var self = win.app.snackbar, x = self.el, y;
                if (x) {
                    if (self.currentTimeout) {
                        clearTimeout(self.currentTimeout);
                        self.currentTimeout = null;
                    }
                    y = x.querySelector('.msg');
                    y.innerHTML = msg;
                    x.classList.add(self.showclass);
                    x.removeAttribute('hidden');
                    self.currentTimeout = setTimeout(function () {
                        x.classList.remove(self.showclass);
                        y.innerHTML = '';
                        self.currentTimeout = null;
                    }, self.timeout);
                }
            },
            hide: function () {
                var self = win.app.snackbar, x = self.el;
                if (x) {
                    x.classList.remove(self.showclass);
                }
                if (self.currentTimeout) {
                    clearTimeout(self.currentTimeout);
                    self.currentTimeout = null;
                }
            },
            showclass: 'open',
            timeout: 3000,
            el: null,
            currentTimeout: null,
        },
        fw: {
            data: {},
            el: null,
            init: function () {
                var self = win.app.fw;
                self.el = document.querySelector('.fwupdate .fwver-text');
                if (self.el) {
                    win.app.mkmenuactive('fwupdate');
                    win.app.curobj = self;
                    self.cur = self;
                    self.get();
                }
            },
            upload: function (e) {
                // Disable navigation during upload
                var nav = document.querySelector('nav');
                if (nav) nav.style.pointerEvents = 'none';
                var cb = function (resp) {
                    var text = '';
                    if (!resp) {
                        text = 'Upload failed';
                        win.app.snackbar.show(text);
                        if (nav) nav.style.pointerEvents = 'auto';
                    } else {
                        text = 'Firmware uploaded. Restarting device...';
                        win.app.snackbar.show(text);
                    }
                    var uploadEl = document.querySelector('.upload-file');
                    if (uploadEl) {
                        uploadEl.innerHTML = '<p>' + text + '</p>';
                    }
                    history.replaceState(null, '', '/');
                };
                win.app.fileupload.upload('/api/v1/fw/update', cb);
                e.preventDefault();
            },
            render: function () {
                var self = win.app.fw;
                var slot = self.el;
                if (!slot) return;
                slot.innerHTML = '';
                var d = self.data;
                if (!d) {
                    slot.innerHTML = '--';
                    return;
                }
                slot.innerHTML = d.version;
            },
            get: function () {
                var self = win.app.fw;
                var callback = function (resp) {
                    if (!resp || !resp.data) return;
                    var d = resp.data;
                    if (d.data && typeof d.data == 'object') {
                        d = d.data;
                    }
                    self.data = d;
                    self.render();
                };
                win.app.load('/api/v1/fw/version', 'json', callback.bind(self));

            },
        },
        home: {
            data: {},
            el: null,
            init: function () {
                var self = win.app.home;
                self.el = document.querySelector('.home .card-body');
                if (self.el) {
                    win.app.mkmenuactive('home');
                    win.app.curobj = self;
                    var t = self.el.querySelector('.table-2');
                    if (!t) self.get();
                }
            },
            render: function () {
                var self = win.app.home;
                var slot = self.el;
                if (!slot) return;
                slot.innerHTML = '';
                var d = self.data, t = null, tr = null, td = null;
                t = document.createElement('table');
                t.className = 'table-2';
                slot.appendChild(t);
                Object.keys(d).forEach(function (key) {
                    tr = document.createElement('tr');
                    td = document.createElement('td');
                    td.innerHTML = String(key).charAt(0).toUpperCase() + String(key).slice(1);
                    tr.appendChild(td);
                    td = document.createElement('td');
                    if(Object.prototype.toString.call(d[key]) === '[object Object]') {
                        if(key === 'storage') {
                            var paths = d[key].paths;
                            if(paths) {
                                paths.forEach(function(k, l) {
                                    var pre = document.createElement('span');
                                    pre.innerHTML = (l > 0 ? '<br>' : '') + k.path.substr(1) + ' ' + win.app.size(k.total_space) + ' / ' + win.app.size(k.free_space);
                                    td.appendChild(pre);
                                });
                            }
                        }
                    } else {
                        td.innerHTML = d[key];
                    }
                    tr.appendChild(td);
                    t.appendChild(tr);
                }
                );
            },
            get: function () {
                var self = win.app.home;
                var callback = function (resp) {
                    if (!resp) {
                        return;
                    }
                    self.data = resp;
                    self.render();
                };
                win.app.load('/api/v1/system/info', 'json', callback.bind(self));
            },
        },
        files: {
            data: {},
            selected: [],
            sortby: 'date',
            sortorder: -1,
            path: '',
            paths: [],
            el: null,
            showall: false,
            init: function () {
                var self = win.app.files;
                self.el = document.querySelector('.files .card-body');
                if (self.el) {
                    win.app.mkmenuactive('files');
                    win.app.curobj = self;
                    self.getpaths();
                }
                var txt = document.querySelector('.files .card-header .selection');
                if (txt) {
                    txt.removeAttribute('hidden');
                    txt.querySelector('.rm').addEventListener('click', function (e) {
                        var v = '';
                        self.selected.forEach(function (el, index) {
                            if (index > 0) v += '|';
                            v += self.mkpath('/', el);
                        });
                        self.sendcmd(v, 'delete');
                        self.selected = [];
                        e.preventDefault();
                    });
                    txt.querySelector('.ar').addEventListener('click', function (e) {
                        var v = '';
                        self.selected.forEach(function (el, index) {
                            if (index > 0) v += '|';
                            v += self.mkpath('/', el);
                        });
                        self.sendcmd(v, 'archive');
                        self.selected = [];
                        e.preventDefault();
                    });
                    txt.querySelector('.dl').addEventListener('click', function (e) {
                        self.selected.forEach(function (el) {
                            var a = document.createElement('a');
                            a.href = baseuri + self.mkpath('/', el);
                            a.setAttribute('download', null);
                            a.click();
                        });
                        self.selected = [];
                        e.preventDefault();
                    });
                }
            },
            upload: function (e) {
                var self = win.app.files;
                var cb = function (resp) {
                    if (!resp) {
                        win.app.snackbar.show('Upload failed');
                    } else {
                        win.app.snackbar.show('Success');
                        self.get(self.path, true);
                    }
                };
                win.app.fileupload.upload('/api/v1/files/' + self.path, cb);
                e.preventDefault();
            },
            render: function () {
                var self = win.app.files;
                if (!self || !self.data) return;
                var f = document.querySelector('.files .info'), g, h, e;
                var d = self.data, i, j, p, q;
                var tr = null, td = null, a = null;
                if (f) {
                    f.innerHTML = '';
                    var paths = self.paths, pathselected = null;
                    for (i = 0, j = paths.length; i < j; i++) {
                        if (self.path.indexOf(paths[i].path.substring(1)) === 0) {
                            pathselected = paths[i];
                            break;
                        }
                    }
                    a = document.createElement('div');
                    g = document.createElement('fieldset');
                    a.appendChild(g);
                    a.className = 'left';
                    g.className = 'path';
                    h = document.createElement('label');
                    h.innerHTML = 'Path: ';
                    g.appendChild(h);
                    p = self.path.split('/');
                    q = '';
                    if (paths && paths.length > 1) {
                        e = document.createElement('select');
                        paths.forEach(function (el) {
                            var o = document.createElement('option');
                            o.value = el.path;
                            o.innerHTML = el.path;
                            o.selected = el.path.substring(1).indexOf(p[0]) === 0;
                            e.appendChild(o);
                        });
                        e.addEventListener('change', function (e) {
                            self.get(e.target.value, true);
                        });
                        g.appendChild(e);
                    } else {
                        for (i = 0, j = p.length; i < j; i++) {
                            if (i == p.length - 1) {
                                g.appendChild(document.createTextNode('/' + p[i]));
                            } else {
                                e = document.createElement('a');
                                e.href = '#';
                                e.innerHTML = p[i];
                                g.appendChild(document.createTextNode('/'));
                                g.appendChild(e);
                                q += '/';
                                q += p[i];
                                e.addEventListener('click', function (num, path) {
                                    return function (e) {
                                        self.get(num == 0 ? '' : path);
                                        e.preventDefault();
                                        return false;
                                    };
                                }(i, q));
                            }
                        }
                    }
                    a.appendChild(g);
                    a.appendChild(document.createTextNode(' '));
                    g = document.createElement('span');
                    g.innerHTML = '(' + (d.data.length + ' files)');
                    a.appendChild(g);
                    a.appendChild(document.createTextNode(' '));
                    g = document.createElement('button');
                    g.className = 'showall outline';
                    g.innerHTML = self.showall ? '-hidden' : '+hidden';
                    g.addEventListener('click', function (e) {
                        e.target.innerHTML = self.showall ? ' +hidden' : ' -hidden';
                        self.showall = self.showall == true ? false : true;
                        self.render();
                        e.preventDefault();
                        return false;
                    });
                    a.appendChild(g);
                    f.appendChild(a);
                    if (pathselected) {
                        a = document.createElement('div');
                        a.className = 'right';
                        g = document.createElement('span');
                        g.className = 'free';
                        g.innerHTML = 'Free: ' + win.app.size(pathselected.free_space);
                        a.appendChild(g);
                        g = document.createElement('span');
                        g.innerHTML = '&nbsp;of&nbsp;';
                        a.appendChild(g);
                        g = document.createElement('span');
                        g.className = 'space';
                        g.innerHTML = win.app.size(pathselected.total_space);
                        a.appendChild(g);
                        f.appendChild(a);
                        a.appendChild(document.createTextNode(' '));
                        g = document.createElement('button');
                        g.className = 'format outline';
                        g.innerHTML = 'Format';
                        a.addEventListener('click', function (s, p) {
                            return function (e) {
                                win.app.dlg(function() {
                                    var cb = function (resp) {
                                        if (!resp) {
                                            win.app.snackbar.show('Failed to format');
                                            return;
                                        }
                                        win.app.snackbar.show('Format done');
                                        s.get();
                                    };
                                    win.app.load('/api/v1/paths/format'+ ((p.indexOf('/') == 0) ? '' : '/') + p, 'json', cb.bind(s), '{"format": true}');
                                }, 'Format ' + p + '?');
                                e.preventDefault();
                            };
                        }(self, pathselected.path));
                        a.appendChild(g);

                    }
                }
                if (d.data && Array.isArray(d.data) && d.data.length > 0) {
                    d = d.data;
                    i = 0, j = d.length;
                    d.sort(win.app.sort(self.sortby, self.sortorder));
                    var slot = self.el;
                    slot.innerHTML = '';
                    p = document.createElement('table');
                    slot.appendChild(p);
                    slot = p;
                    g = document.createElement('thead');
                    tr = document.createElement('tr');
                    td = document.createElement('th');
                    a = document.createElement('input');
                    a.type = 'checkbox';
                    a.addEventListener('click', function (e) {
                        var x = e.target.checked;
                        var y = document.querySelectorAll('.files tbody input[type=checkbox]');
                        y.forEach(function (el) {
                            el.checked = x;
                            if (x) self.selected.push(el.dataset.file);
                        });
                        if (!x) self.selected = [];
                        var z = document.querySelector('.files .card-header .selection');
                        if (z) {
                            if (self.selected.length) z.classList.remove('hide');
                            else z.classList.add('hide');
                        }
                    });
                    td.appendChild(a);
                    tr.appendChild(td);
                    var keys = Object.keys(d[0]);
                    keys.forEach(function (key, index) {
                        td = document.createElement('th');
                        if (index > keys.length - 3) {
                            td.className = 'hide-xs';
                        }
                        td.innerHTML = String(key).charAt(0).toUpperCase() + String(key).slice(1)
                            + '<span' + (key === self.sortby ? ' class="sort' + (self.sortorder === 1 ? ' up' : '') : '')
                            + '">&nbsp</spanclass=>';
                        td.addEventListener('click', function (key, a) {
                            return function (e) {
                                a.sortby = key;
                                a.sortorder = -a.sortorder;
                                a.render();
                                e.preventDefault();
                            };
                        }(key, self));
                        tr.appendChild(td);
                    });
                    td = document.createElement('th');
                    td.innerHTML = 'Actions';
                    tr.appendChild(td);
                    g.appendChild(tr);
                    slot.appendChild(g);
                    g = document.createElement('tbody');
                    slot.appendChild(g);
                    for (var file, name; i < j; i++) {
                        file = d[i];
                        name = file.name;
                        if (!self.showall && (name.indexOf('.') === 0 || (file.type === 'd' && name !== 'Archive') || name.substring(name.length - 4) === '.bak')) continue;
                        tr = document.createElement('tr');
                        td = document.createElement('td');
                        if (file.type === 'd' || file.mode === 'r') {
                            tr.className = 'dir';
                            td.innerHTML = '&nbsp;';
                        } else {
                            a = document.createElement('input');
                            a.type = 'checkbox';
                            a.dataset.file = name;
                            a.addEventListener('click', function (e) {
                                var x = e.target.checked;
                                if (x) {
                                    self.selected.push(e.target.dataset.file);
                                } else {
                                    self.selected = self.selected.filter(function (el) {
                                        return el !== e.target.dataset.file;
                                    });
                                }
                                var z = document.querySelector('.files .card-header .selection');
                                if (z) {
                                    if (self.selected.length) z.classList.remove('hide');
                                    else z.classList.add('hide');
                                }
                            });
                            td.appendChild(a);
                        }
                        tr.appendChild(td);
                        td = document.createElement('td');
                        a = document.createElement('a');
                        a.href = name;
                        a.addEventListener('click', function (file, n) {
                            return function (e) {
                                if (file.type === 'f') {
                                    e.target.href = baseuri + '/' + self.path + '/' + n;
                                    return true;
                                } else if (file.type === 'd') {
                                    self.get(n);
                                }
                                e.preventDefault();
                            };
                        }(file, name));
                        a.innerHTML = name;
                        td.appendChild(a);
                        tr.appendChild(td);
                        td = document.createElement('td');
                        td.innerHTML = file.date;
                        tr.appendChild(td);
                        td = document.createElement('td');
                        td.innerHTML = (file.type === 'd') ? '-' : win.app.size(file.size);
                        tr.appendChild(td);
                        td = document.createElement('td');
                        td.className = 'hide-xs';
                        td.innerHTML = file.type;
                        tr.appendChild(td);
                        td = document.createElement('td');
                        td.className = 'hide-xs';
                        td.innerHTML = file.mode;
                        tr.appendChild(td);
                        td = document.createElement('td');
                        if (file.type === 'f' && file.mode === 'rw') {
                            e = document.createElement('div');
                            e.setAttribute('role', 'group');
                            e.dataset.file = name;
                            a = document.createElement('button');
                            a.className = 'outline rm';
                            win.app.showsvg(a, 'M280-120q-33 0-56.5-23.5T200-200v-520h-40v-80h200v-40h240v40h200v80h-40v520q0 33-23.5 56.5T680-120H280Zm400-600H280v520h400v-520ZM360-280h80v-360h-80v360Zm160 0h80v-360h-80v360ZM280-720v520-520Z', 'var(--pico-primary)', 24, 24);
                            a.addEventListener('click', function (file) {
                                return function (e) {
                                    self.sendcmd(file, 'delete');
                                    e.preventDefault();
                                };
                            }(file.name));
                            e.appendChild(a);
                            a = document.createElement('button');
                            a.className = 'outline ar';
                            win.app.showsvg(a, 'm480-240 160-160-56-56-64 64v-168h-80v168l-64-64-56 56 160 160ZM200-640v440h560v-440H200Zm0 520q-33 0-56.5-23.5T120-200v-499q0-14 4.5-27t13.5-24l50-61q11-14 27.5-21.5T250-840h460q18 0 34.5 7.5T772-811l50 61q9 11 13.5 24t4.5 27v499q0 33-23.5 56.5T760-120H200Zm16-600h528l-34-40H250l-34 40Zm264 300Z', 'var(--pico-primary)', 24, 24);
                            a.addEventListener('click', function (file) {
                                return function (e) {
                                    self.sendcmd(file, 'archive');
                                    e.preventDefault();
                                };
                            }(name, self));
                            e.appendChild(a);
                            td.appendChild(e);
                        }
                        else td.innerHTML = '&nbsp;';
                        tr.appendChild(td);
                        g.appendChild(tr);
                    }
                }
            },
            getpaths() {
                var self = win.app.files;
                var callback = function (resp) {
                    if (resp && resp.paths && Array.isArray(resp.paths)) {
                        self.paths = resp.paths;
                    }
                    self.get();
                };
                win.app.load('/api/v1/paths', 'json', callback.bind(self));
            },
            mkpath(base, name) {
                var self = win.app.files, path = base;
                if (name && name.length > 0) {
                    if (!(self.path.indexOf(name.substring(1)) === 0)) {
                        path += ((path[path.length - 1] === '/' || self.path[0] === '/') ? '' : '/') + self.path;
                    }
                    path += ((path[path.length - 1] === '/' || name[0] === '/') ? '' : '/') + name;
                }
                return path;
            },
            get(name, plain) {
                var self = win.app.files;
                var callback = function (resp) {
                    if (!resp) {
                        return;
                    }
                    if (resp && resp.path && Array.isArray(resp.data)) {
                        self.data = resp;
                        if (resp.path) {
                            if (resp.path[0] === '/') {
                                self.path = resp.path.substr(1);
                            } else {
                                self.path = resp.path;
                            }
                            if (resp.path[resp.path.length - 1] === '/') {
                                self.path = self.path.substr(0, self.path.length - 1);
                            }
                        }
                        self.render();
                    }
                };
                if (plain) win.app.load('/api/v1/files' + (name[0] !== '/' ? '/' : '') + name, 'json', callback.bind(self));
                else win.app.load(self.mkpath('/api/v1/files', name), 'json', callback.bind(self));
            },
            sendcmd(name, action) {
                var self = win.app.files;
                win.app.dlg(function() {
                    var cb = function (resp) {
                        if (!resp) {
                            win.app.snackbar.show('Failed ' + action);
                            return;
                        }
                        win.app.snackbar.show(action + 'd');
                        self.get(self.path, true);
                    };
                    if (name[0] !== '/' && name.indexOf('|') < 0) name = self.mkpath('/', name);
                    win.app.load('/api/v1/files/' + action, 'json', cb.bind(self), '{"name":"' + name + '"}');
                    return false;
                }, 'Really ' + action + '?');
            }
        },
        dlg(fn, msg) {
            var dialog = document.querySelector('dialog');
            if (dialog) {
                var okl = null;
                var f = function () {
                    return function () {
                        if(okl) okl.remove();
                        dialog.close();
                        fn();
                        return false;
                    };
                };
                var msgsel = dialog.querySelector('.msg');
                if(msgsel)
                    msgsel.innerHTML = msg ? msg : 'Are you sure?';
                var okbtn = dialog.querySelector('.ok');
                if(okbtn)
                    okbtn.addEventListener('click', f());
                dialog.removeAttribute('hidden');
                dialog.showModal();
            }
        },
        config: {
            init: function () {
                var self = win.app.config;
                self.el = document.querySelector('.config .card-body');
                if (self.el) {
                    win.app.mkmenuactive('config');
                    win.app.curobj = self;
                    self.get();
                }
                var a = document.querySelector('.config .card-header .config-cmd-reset');
                if(a) {
                    a.addEventListener('click', function () {
                        return function (e) {
                            win.app.dlg(function() {
                                var cb = function (resp) {
                                    if (!resp) {
                                        win.app.snackbar.show('Failed to reset');
                                        return;
                                    }
                                    win.app.snackbar.show('Reset done');
                                    self.get();
                                };
                                win.app.load('/api/v1/config/reset_to_defaults', 'json', cb.bind(self));
                            }, 'Reset config?');
                            e.preventDefault();
                        };
                    }(self));
                }
            },
            get: function () {
                var self = win.app.config;
                var callback = function (resp) {
                    if (!resp) {
                        return;
                    }
                    if (resp && resp && Array.isArray(resp)) {
                        self.data = resp;
                        self.render();
                    }
                };
                win.app.load('/api/v1/config', 'json', callback.bind(self));
            },
            save: function (name, value) {
                var self = win.app.config, cur = null, data = '', val = value;
                var callback = function (resp) {
                    if (!resp) {
                        win.app.snackbar.show('Failed save');
                        return;
                    }
                    if (resp && resp.data && Array.isArray(resp.data)) {
                        self.data = resp.data;
                        self.render();
                    } else {
                        cur.value = val;
                    }
                    win.app.snackbar.show('Saved');
                };
                cur = self.find_in_data(name);
                if (!cur) return;
                data = '{"name":"' + name + '","value":';
                if (cur.type !== 'int' && cur.type !== 'bool' && cur.type !== 'float') data += '"';
                if (cur.type === 'int' || cur.type === 'float') { val = parseFloat(value); }
                else if (cur.type === 'bool') { val = value ? 1 : 0; }
                data += val;
                if (cur.type !== 'int' && cur.type !== 'bool' && cur.type !== 'float') data += '"';
                data += '}';
                win.app.load('/api/v1/config/' + name, 'json', callback.bind(self), data);
            },
            find_in_data: function (name) {
                var self = this, i, g;
                if (!self.data || !Array.isArray(self.data)) return null;
                
                // Check if data is grouped (has group_id) or flat
                if (self.data.length > 0 && self.data[0].group_id !== undefined) {
                    // Grouped mode: iterate through groups and their items
                    for (g = 0; g < self.data.length; g++) {
                        var group = self.data[g];
                        if (group.items && Array.isArray(group.items)) {
                            for (i = 0; i < group.items.length; i++) {
                                if (group.items[i].name === name) {
                                    return group.items[i];
                                }
                            }
                        }
                    }
                } else {
                    // Flat mode: iterate through data directly
                    for (i = 0; i < self.data.length; i++) {
                        if (self.data[i].name === name) {
                            return self.data[i];
                        }
                    }
                }
                return null;
            },
            render: function () {
                var self = win.app.config;
                if (!self.data) return;
                var data = self.data;
                var slot = self.el;
                slot.innerHTML = '';
                var items = data[0].group_id === undefined ? data : 0;

                function createConfigRow(el) {
                    var tr = document.createElement('tr'), x;
                    if (el.depends) {
                        tr.classList.add('depends');
                        tr.dataset.depends = el.depends;
                        x = items && items.find(function (el2) {
                            return el2.name === el.depends;
                        }) || null;
                        if (x && x.value === 0) {
                            tr.classList.add('hide');
                        }
                    }
                    var td = document.createElement('td');
                    td.className = 'name';
                    td.innerHTML = String(el.name).charAt(0).toUpperCase() + String(el.name).slice(1);
                    tr.appendChild(td);
                    td = document.createElement('td');
                    td.className = 'value';
                    var input, opt, val, k, l;
                    if (el.toggles) {
                        for (k = 0, l = el.toggles.length; k < l; k++) {
                            input = document.createElement('button');
                            input.innerHTML = el.toggles[k].title;
                            if ((el.value & (1 << (el.toggles[k].pos))) === 0) {
                                input.className = 'outline';
                                input.dataset.value = 0;
                            } else {
                                input.className = '';
                                input.dataset.value = 1;
                            }
                            input.dataset.pos = el.toggles[k].pos;
                            input.dataset.name = el.name;
                            input.dataset.raw = el.value;
                            input.addEventListener('click', function () {
                                return function (e) {
                                    var x = e.target;
                                    var w = x.dataset.value == 1 ? 0x01 : 0x00;
                                    var v = parseFloat(x.dataset.pos);
                                    var j = self.find_in_data(x.dataset.name);
                                    if(!j || !j.value) return;
                                    var i = parseFloat(j.value);
                                    if (w === 1) {
                                        (i &= ~(1 << v));
                                        x.dataset.value = 0;
                                        x.className = 'outline';
                                    } else {
                                        (i |= (1 << v));
                                        x.dataset.value = 1;
                                        x.className = '';
                                    }
                                    self.save(x.dataset.name, i);
                                };
                            }());
                            td.appendChild(input);
                        }
                    } else if (el.values) {
                        input = document.createElement('select');
                        for (k = 0, l = el.values.length; k < l; k++) {
                            opt = document.createElement('option');
                            val = el.values[k];
                            opt.value = val.value + '';
                            opt.selected = val.value === el.value;
                            opt.innerHTML = val.title;
                            input.appendChild(opt);
                        }
                        input.addEventListener('change', function (e) {
                            var x = e.target;
                            var y = x.options[x.selectedIndex];
                            self.save(x.name, y.value);
                        });
                    } else {
                        input = document.createElement('input');
                        if (el.type === 'bool') {
                            input.type = 'checkbox';
                            input.checked = (el.value === 'true' || el.value === 1 || el.value === '1' || el.value === true);
                            input.role = 'switch';
                            input.addEventListener('change', function (e) {
                                var x = e.target;
                                self.save(x.name, x.checked ? 1 : 0);
                                var y = document.querySelectorAll('.card-body tr[data-depends="' + x.name + '"]');
                                y.forEach(function (el) {
                                    if (x.checked) {
                                        el.classList.remove('hide');
                                    } else {
                                        el.classList.add('hide');
                                    }
                                });
                            });
                        } else if (el.type === 'int') {
                            input.type = 'range';
                            input.step = el.step || 1;
                            input.min = el.min || 0;
                            input.max = el.max || el.value + 100;
                            input.value = el.value + '';
                        } else {
                            input.value = el.value + '';
                            input.type = 'text';
                            input.addEventListener('keyup', function (e) {
                                var x = e.target;
                                if (e.keyCode === 13) {
                                    self.save(x.name, x.value);
                                }
                            });
                        }
                    }
                    if (!el.toggles) {
                        input.name = el.name;
                        td.appendChild(input);
                        if (el.type === 'int' && input.type === 'range') {
                            var valspan = document.createElement('span');
                            valspan.className = 'right';
                            valspan.innerHTML = el.value;
                            td.appendChild(valspan);
                            input.addEventListener('input', function (e) {
                                var x = e.target;
                                valspan.innerHTML = x.value;
                            });
                            input.addEventListener('change', function name(e) {
                                var x = e.target;
                                self.save(x.name, x.value);
                            });
                        }
                    }
                    tr.appendChild(td);
                    td = document.createElement('td');
                    td.innerHTML = el.info;
                    td.className = 'info';
                    tr.appendChild(td);
                    return tr;
                }
                if(data.length > 0) {
                    if (items === 0) {
                        // Grouped mode
                        data.forEach(function(item) {
                            items = item.items;
                            var grp = document.createElement('details');
                            grp.className = 'config-group';
                            var grplabel = document.createElement('summary');
                            grplabel.innerHTML = item.group_name || 'Default';
                            grplabel.addEventListener('click', function() {
                                var t = grp.querySelector('table');
                                if (t) {
                                    t.classList.toggle('hide');
                                    grplabel.classList.toggle('tiny');
                                }
                            });
                            grplabel.classList.add('left');
                            grplabel.setAttribute('role', 'button');
                            grplabel.classList.add('secondary');
                            grp.appendChild(grplabel);
                            var table = document.createElement('table');
                            grp.appendChild(table);
                            if (item.default_hidden) {
                                table.classList.add('hide');
                                grplabel.classList.add('tiny');
                            } else {
                                grp.setAttribute('open', '');
                            }
                            // Create thead
                            // Create tbody
                            var tbody = document.createElement('tbody');
                            table.appendChild(tbody);
                            items.forEach(function(el) {
                                tbody.appendChild(createConfigRow(el));
                            });
                            slot.appendChild(grp);
                        });
                    } else {
                        // Old way
                        var table = document.createElement('table');
                        slot.appendChild(table);
                        var tbody = document.createElement('tbody');
                        table.appendChild(tbody);
                        items.forEach(function(el) {
                            if (!el || !el.name) return;
                            tbody.appendChild(createConfigRow(el));
                        });
                    }
                    var x = slot.querySelector('[name=log_format]');
                    var y = slot.querySelector('[name=log_ubx_nav_sat]');
                    if(x && y) {
                        var tr = y.closest('tr');
                        var updateUbxNavSatVisibility = function () {
                            var option = x.options[x.selectedIndex];
                            var selectedFormat = option
                                ? String(option.text || option.innerText || '').trim().toLowerCase()
                                : '';
                            if (selectedFormat !== 'ubx') {
                                tr.classList.add('hide');
                            } else {
                                tr.classList.remove('hide');
                            }
                        };
                        updateUbxNavSatVisibility();
                        x.addEventListener('change', updateUbxNavSatVisibility);
                    }
                    
                }
            },
            data: {},
            el: null,
        }
    };
})(window);

document.addEventListener('DOMContentLoaded', function () {
    var self = window.app;
    self.init();
});