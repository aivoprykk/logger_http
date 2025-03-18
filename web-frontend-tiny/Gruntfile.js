const { title } = require('process');

module.exports = function (grunt) {
    'use strict';

    // Force use of Unix newlines
    grunt.util.linefeed = '\n';

    RegExp.quote = function (string) {
        return string.replace(/[-\\^$*+?.()|[\]{}]/g, '\\$&');
    };

    var fs = require('fs');
    var path = require('path');
    var sass = require('sass');

    require('load-grunt-tasks')(grunt, { scope: 'devDependencies' });
    grunt.loadNpmTasks('grunt-replace');

    // Project configuration.
    grunt.initConfig({
        publicDir: 'dist',
        srcDir: 'src',
        concat: {
            js: {
                options: {
                    stripBanners: false,
                },
                src: [
                    '<%=srcDir%>/index.js'
                ],
                dest: '<%=publicDir%>/index.js'
            },
        },
        copy: {
            png: {
                expand: true,
                cwd: '<%=srcDir%>/assets/',
                src: 'logo.png',
                dest: '<%=publicDir%>/',
                filter: 'isFile'
            },
        },
        sass: {
            options: {
                implementation: sass,
                sourceMap: false
            },
            dist: {
                files: {
                    '<%=publicDir%>/index.css': '<%=srcDir%>/index.scss'
                }
            }
        },
        clean: {
            dist: [
                '<%=publicDir%>/***',
            ]
        },
        pug: {
            debug: {
                options: {
                    data: {
                        debug: true,
                        title: 'ESP-GPS'
                    },
                    pretty: true
                },
                files: {
                    '<%=publicDir%>/index.html': '<%=srcDir%>/index.pug',
                    '<%=publicDir%>/config.html': '<%=srcDir%>/config.pug',
                    '<%=publicDir%>/files.html': '<%=srcDir%>/files.pug',
                    '<%=publicDir%>/fwupdate.html': '<%=srcDir%>/fwupdate.pug'
                }
            },
            release: {
                options: {
                    data: {
                        debug: false,
                        title: 'Home'
                    }
                },
                files: {
                    '<%=publicDir%>/index.html': '<%=srcDir%>/index.pug',
                    '<%=publicDir%>/config.html': '<%=srcDir%>/config.pug',
                    '<%=publicDir%>/files.html': '<%=srcDir%>/files.pug',
                    '<%=publicDir%>/fwupdate.html': '<%=srcDir%>/fwupdate.pug'
                }
            }
        },
        uglify: {
            debug: {
                options: {
                    beautify: true
                },
                files: {
                    '<%=publicDir%>/index.js': ['<%=publicDir%>/index.js']
                }
            },
            release: {
                options: {
                    beautify: false
                },
                files: {
                    '<%=publicDir%>/index.js': ['<%=publicDir%>/index.js']
                }
            }
        },
        cssmin: {
            sitecss: {
                options: {
                    banner: ''
                },
                files: {
                    '<%=publicDir%>/index.css': [
                        '<%=publicDir%>/index.css',
                    ]
                }
            }
        },
        replace: {
            release: {
                options: {
                    patterns: [
                        {
                            match: 'index.scss',
                            replacement: 'index.css'
                        },
                    ],
                    usePrefix: false
                },
                files: [
                    {
                        expand: true, flatten: true, src: [
                            '<%=publicDir%>/index.html',
                            '<%=publicDir%>/config.html',
                            '<%=publicDir%>/files.html',
                            '<%=publicDir%>/fwupdate.html',
                        ], dest: '<%=publicDir%>/'
                    }
                ]
            },
            debug: {
                options: {
                    patterns: [
                        { match: 'index.scss', replacement: 'index.css' }
                    ],
                    usePrefix: false
                },
                files: [
                    {
                        expand: true, flatten: true, src: [
                            '<%=publicDir%>/index.html',
                            '<%=publicDir%>/config.html',
                            '<%=publicDir%>/files.html',
                            '<%=publicDir%>/fwupdate.html',
                        ], dest: '<%=publicDir%>/'
                    }
                ]
            }
        }
    });

    grunt.registerTask('debug', ['clean', 'sass', 'concat:js', 'copy:png', 'pug:debug', 'replace:debug']);
    grunt.registerTask('release', ['clean', 'sass', 'concat:js', 'copy:png', 'pug:release', 'uglify:release', 'cssmin:sitecss', 'replace:release']);
    grunt.registerTask('dist', ['release']);
    grunt.registerTask('default', ['dist']);
};
