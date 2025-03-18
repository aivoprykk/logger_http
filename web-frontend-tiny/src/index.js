(function (win) {
    var baseuri = '';
    if (process.env.NODE_ENV === 'development') {
        // baseuri = 'http://esp-9c40.local';
        baseuri = 'http://esp-9c40.local';
    }
    win.app = {
        curobj: null,
        init: function () {
            this.snackbar.init();
            window.app.fw.init();
            window.app.files.init();
            window.app.config.init();
            window.app.home.init();
            console.log('Hello from ' + win.location.href);
            var el = document.createElement('dialog');
            el.innerHTML = '<article><h3>Confirm your action!</h3><p>Are you sure you want to delete the item?</p><footer><button class="secondary outline cancel" href="#cancel" role="button">Cancel</button><button class="outline ok" href="#confirm" role="button">Proceed</button><footer></article>';
            document.body.appendChild(el);
            var closebtn = document.querySelector('dialog .cancel');
            if (el) {
                closebtn.addEventListener('click', function () {
                    el.close();
                    return false;
                });
            }
            el = document.querySelector('nav .brand');
            var a = document.createElement('span');
            a.className = 'sm';
            a.innerHTML = 'GPS';
            el.appendChild(a);
        },
        mkmenuactive: function (cl) {
            var i, j;
            var a = document.querySelectorAll('header nav li');
            for (i = 0, j = a.length; i < j; i++) {
                if(a[i].classList.contains(cl)) {
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
                if (xhr.readyState === 4) {
                    callback(xhr.response);
                }
            };
            xhr.open(data ? 'POST' : 'GET', baseuri + url, true);
            if (data && type === 'json') {
                xhr.setRequestHeader('Content-Type', 'application/json');
                if (data && typeof data === 'object') {
                    d = JSON.stringify(data);
                } else d = data;
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
            upload: function (url, btn, callback) {
                if (!btn) {
                    console.log('Button object missing.');
                    return;
                }
                var file = btn.parentNode.querySelector('input[type=file]'), size = 0;
                if (file && file.files && file.files.length > 0) {
                    var data = new FormData();
                    data.append('file', file.files[0]);
                    size  = file.files[0].size;
                } else {
                    if (file)
                        console.log('Please select a file first.');
                    else
                        console.log('File input missing.');
                    return;
                }
                var b = file.parentNode.querySelector('button');
                var txt = file.parentNode.querySelector('.file-text');
                var textupdate = function (msg) {
                    if (txt) {
                        txt.innerHTML = msg;
                    }
                };
                var xhr = new XMLHttpRequest();
                xhr.onreadystatechange = function () {
                    if (xhr.readyState == 4) {
                        if (xhr.status == 200) {
                            textupdate('Uploaded!');
                            win.app.snackbar.show('Success');
                            win.app.fileupload.filedone('Upload file', false);
                            if (callback) {
                                callback(xhr.response);
                            }
                        }
                        else {
                            textupdate('Error!');
                            win.app.snackbar.show('Upload failed.');
                            if (b) {
                                b.style.display = '';
                            }
                        }
                    }
                };
                xhr.upload.onprogress = function (e) {
                    if (e.lengthComputable) {
                        if (e.loaded < size) {
                            var percent = Math.ceil(e.loaded / size * 100);
                            textupdate('Uploading... ' + percent + '%');
                        }
                        else if(e.loaded >= size) {
                            textupdate('Uploading... 100%');
                        }
                    }
                };
                xhr.open('post', baseuri + url, true);
                xhr.timeout = 45000;
                xhr.send(data);
                if (b) {
                    b.style.display = 'none';
                }
            },
            fileselected: function (event, file) {
                if (file && file.files && file.files.length > 0) {
                    var obj = file.files[0];
                    var name = obj.name;
                    var fileName = name.split('\\|/');
                    win.app.fileupload.filedone('Selected ' + fileName[fileName.length - 1] + ' (' + win.app.size(obj.size) + ')', true);
                    event.preventDefault();
                }
            },
            filedone: function (msg, display) {
                var txt = document.querySelector('.file-text');
                if (txt) {
                    txt.innerHTML = msg;
                    txt = document.querySelector('.upload-file .upload-submit');
                    if (txt) {
                        txt.style.display = display ? '' : 'none';
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
                    y = x.querySelector('.msg');
                    y.innerHTML = msg;
                    x.className += ' ' + self.showclass;
                    x.removeAttribute('hidden');
                    setTimeout(function () {
                        x.className = x.className.replace(self.showclass, '');
                        y.innerHTML = '';
                    }, self.timeout);
                }
            },
            hide: function () {
                var self = win.app.snackbar, x = self.el;
                if (x) {
                    x.className = x.className.replace(self.showclass, '');
                }
            },
            showclass: 'open',
            timeout: 2000,
            el: null,
        },
        fw: {
            data: {},
            el: null,
            init: function () {
                var self = win.app.fw;
                self.el = document.querySelector('.fwupdate .fwver-text');
                if (self.el) {
                    win.app.mkmenuactive('fwupdate');
                    self.cur = self;
                    self.get();
                }
            },
            upload: function (e, btn) {
                var self = win.app.fw;
                var cb = function (resp) {
                    if (!resp) {
                        win.app.snackbar.show('Upload failed');
                        return;
                    }
                    win.app.snackbar.show('Success');
                    self.get();
                };
                win.app.fileupload.upload('/api/v1/fw/update', btn, cb);
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
                console.log(d.version);
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
                    if(!t) self.get();
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
                    td.innerHTML = d[key];
                    tr.appendChild(td);
                    t.appendChild(tr);
                }
                );
            },
            get: function () {
                var self = win.app.home;
                var callback = function (resp) {
                    if (!resp) {
                        console.log('Error on loading index');
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
                    txt.style.display = 'none';
                    txt.removeAttribute('hidden');
                    txt.querySelector('.rm').addEventListener('click', function (e) {
                        var v = '';
                        self.selected.forEach(function (el, index) {
                            if (index > 0) v += '|';
                            v += self.mkpath('/', el);
                        });
                        self.sendcmd(v, 'delete');
                        self.selected = [];
                        txt.style.display = 'none';
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
                        txt.style.display = 'none';
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
                        txt.style.display = 'none';
                        e.preventDefault();
                    });
                }
            },
            upload: function (e, btn) {
                var self = win.app.files;
                var cb = function (resp) {
                    if (!resp) {
                        win.app.snackbar.show('Upload failed');
                        console.log('Error on uploading file');
                        return;
                    }
                    win.app.snackbar.show('Success');
                    console.log('Uploaded file');
                    self.get();
                };
                win.app.fileupload.upload('/api/v1/files/' + self.path, btn, cb);
            },
            render: function () {
                var self = win.app.files;
                if (!self || !self.data) return;
                var f = document.querySelector('.files .info'), g, e;
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
                    g = document.createElement('span');
                    a.appendChild(g);
                    a.className = 'left';
                    g.className = 'path';
                    g.appendChild(document.createTextNode('Path: '));
                    g.innerHTML = 'Path: ';
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
                    }
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
                            z.style.display = self.selected.length ? '' : 'none';
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
                        td.innerHTML = String(key).charAt(0).toUpperCase() + String(key).slice(1);
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
                                    z.style.display = self.selected.length ? '' : 'none';
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
                                console.log('Download ' + n);
                                if (file.type === 'f') {
                                    e.target.href = baseuri + '/api/v1/files/' + self.path + '/' + n;
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
                                    console.log('Remove ' + file);
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
                                    console.log('Archive ' + file);
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
                    if (!resp) {
                        console.log('Error on loading paths');
                    }
                    else if (resp && resp.paths && Array.isArray(resp.paths)) {
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
                        console.log('Error on loading files');
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
                if(plain) win.app.load('/api/v1/files'+name, 'json', callback.bind(self));
                else win.app.load(self.mkpath('/api/v1/files', name), 'json', callback.bind(self));
            },
            sendcmd(name, action) {
                var self = win.app.files;
                var dialog = document.querySelector('dialog');
                if (dialog) {
                    var okbtn = document.querySelector('dialog .ok');
                    var f = function (l) {
                        return function () {
                            dialog.close();
                            if (l) l.remove();
                            var callback = function (resp) {
                                if (!resp) {
                                    console.log('Error on ' + action + ' file');
                                    win.app.snackbar.show('Failed ' + action);
                                    return;
                                }
                                console.log(action + ' file done');
                                win.app.snackbar.show(action + 'd');
                                self.get();
                            };
                            win.app.load('/api/v1/files/' + action, 'json', callback.bind(self), '{"name":"' + name + '"}');
                            return false;
                        };
                    };
                    var listener = okbtn.addEventListener('click', f(listener));
                    dialog.removeAttribute('hidden');
                    dialog.showModal();
                }
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
            },
            get: function () {
                var self = win.app.config;
                var callback = function (resp) {
                    if (!resp) {
                        console.log('Error on loading config');
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
                        console.log('Error on saving config');
                        self.snackbar.show('Failed save');
                        return;
                    }
                    console.log('Saved config');
                    if (resp && resp.data && Array.isArray(resp.data)) {
                        self.data = resp.data;
                        self.render();
                    } else {
                        cur.value = val;
                    }
                    win.app.snackbar.show('Saved');
                };
                for (var i = 0, j = self.data.length, el = null; i < j; ++i) {
                    el = self.data[i];
                    if (el.name === name) {
                        cur = el;
                        break;
                    }
                }
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
            render: function () {
                var self = win.app.config;
                if (!self.data) return;
                var data = self.data, tr = null,
                    td = null, input = null, opt = null, val = null, el = null;
                var i = 0, j = data.length, k = 0, l = 0;
                var slot = self.el;
                slot.innerHTML = '';
                el = document.createElement('table');
                slot.appendChild(el);
                slot = el;
                el = document.createElement('thead');
                tr = document.createElement('tr');
                td = document.createElement('th');
                td.innerHTML = 'Name';
                tr.appendChild(td);
                td = document.createElement('th');
                td.innerHTML = 'Value';
                tr.appendChild(td);
                td = document.createElement('th');
                td.innerHTML = 'Info';
                tr.appendChild(td);
                el.appendChild(tr);
                slot.appendChild(el);
                el = document.createElement('tbody');
                slot.appendChild(el);
                slot = el;
                for (; i < j; ++i) {
                    el = data[i];
                    if (!el || !el.name) continue;
                    tr = document.createElement('tr');
                    td = document.createElement('td');
                    td.className = 'name';
                    td.innerHTML = String(el.name).charAt(0).toUpperCase() + String(el.name).slice(1);
                    tr.appendChild(td);
                    td = document.createElement('td');
                    td.className = 'value';
                    if (!el.toggles) {
                        input = document.createElement(el.values ? 'select' : 'input');
                    }
                    if (el.toggles) {
                        for (k = 0, l = el.toggles.length; k < l; k++) {
                            input = document.createElement('button');
                            input.innerHTML = el.toggles[k].title;
                            if ((el.value & (1 << (el.toggles[k].pos))) === 0) { // test bit
                                input.className = 'outline';
                                input.dataset.value = 0;
                            } else {
                                input.className = '';
                                input.dataset.value = 1;
                            }
                            input.dataset.pos = el.toggles[k].pos;
                            input.dataset.name = el.name;
                            input.addEventListener('click', function (obj) {
                                return function (e) {
                                    var i = obj;
                                    var x = e.target;
                                    var w = x.dataset.value == 1 ? 0x01 : 0x00;
                                    var v = parseFloat(x.dataset.pos);
                                    if (w === 1) {
                                        (i &= ~(1 << v)); // clear bit
                                        x.dataset.value = 0;
                                        x.className = 'outline';
                                    } else {
                                        (i |= (1 << v)); // set bit
                                        x.dataset.value = 1;
                                        x.className = '';
                                    }
                                    console.log('Change ' + x.dataset.name + ' from ' + obj + ' to ' + i);
                                    self.save(x.dataset.name, i);
                                };
                            }(el.value));
                            td.appendChild(input);
                        }
                    }
                    else if (el.values) {
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
                            console.log('Change ' + x.name + ' to ' + y.value);
                            self.save(x.name, y.value);
                        }
                        );
                    } else {
                        if (el.type === 'bool') {
                            input.type = 'checkbox';
                            input.checked = (el.value === 'true' || el.value === 1 || el.value === '1' || el.value === true);
                            input.role = 'switch';
                            input.addEventListener('change', function (e) {
                                var x = e.target;
                                console.log('Change ' + x.name + ' to ' + x.checked);
                                self.save(x.name, x.checked ? 1 : 0);
                            });
                        }
                        else {
                            input.value = el.value + '';
                            input.type = 'text';
                            input.addEventListener('keyup', function (e) {
                                var x = e.target;
                                if (e.keyCode === 13) {   // Enter key
                                    console.log('Change ' + x.name + ' to ' + x.value);
                                    self.save(x.name, x.value);
                                }
                            });
                        }
                    }
                    if (!el.toggles) {
                        input.name = el.name;
                        td.appendChild(input);
                    }
                    tr.appendChild(td);
                    td = document.createElement('td');
                    td.innerHTML = el.info;
                    td.className = 'info';
                    tr.appendChild(td);
                    slot.appendChild(tr);
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
    var i; var j;
    var obj = document.querySelector('main .upload-file');
    if (obj) {
        i = obj.querySelector('input[type=file]');
        j = obj.querySelector('.upload-submit');
    }
    if (i) {
        i.addEventListener('change', function (event) {
            self.fileupload.fileselected(event, i);
        });
    }
    if (j) {
        j.innerHTML = '';
        j.style.display = 'none';
        self.showsvg(j, 'M440-320v-326L336-542l-56-58 200-200 200 200-56 58-104-104v326h-80ZM240-160q-33 0-56.5-23.5T160-240v-120h80v120h480v-120h80v120q0 33-23.5 56.5T720-160H240Z', 'var(--pico-primary)', 24, 24);
        j.addEventListener('click', function (e) {
            self.curobj.upload(e, j);
        });
    }
});