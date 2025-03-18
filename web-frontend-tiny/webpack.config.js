const path = require('path');
const CompressionPlugin = require('compression-webpack-plugin');
const HtmlBundlerPlugin = require('html-bundler-webpack-plugin');
const isProd = process.env.NODE_ENV === 'production';
module.exports = {
    mode: isProd ? 'production' : 'development',
    output: {
        path: path.resolve(__dirname, './public'),
        clean: true,
    },
    // devtool: 'eval-source-map',
    module: {
        rules: [
            {
                test: /\.((sa|sc|c)ss)$/,
                exclude: /node_modules/,
                use: [
                    {
                        loader: 'css-loader', // translates CSS into CommonJS modules
                    },
                    {
                        loader: 'sass-loader',
                        options: {
                            sassOptions: {
                                silenceDeprecations: ['mixed-decls', 'color-functions', 'global-builtin', 'import'],
                            }
                        }
                    }
                ]
            },
            {
                test: /\.(ico|png|jp?g|webp|svg)$/,
                type: 'asset/resource',
                generator: {
                    filename: '[name][ext][query]',
                },
            },
            {
                test: /\.(woff|woff2|eot|ttf)$/,
                use: {
                    loader: 'url-loader',
                },
            },
        ]
    },
    plugins: [
        new HtmlBundlerPlugin({
            entry: [
                // define many page templates here
                {
                    import: __dirname + '/src/index.pug', // => dist/index.html
                    filename: 'index.html',
                    data: { title: 'Home' },
                },
                {
                    import: __dirname + '/src/files.pug', // => dist/about.html
                    filename: 'files.html',
                    data: { title: 'Files' },
                },
                {
                    import: __dirname + '/src/config.pug', // => dist/about.html
                    filename: 'config.html',
                    data: { title: 'Config' },
                },
                {
                    import: __dirname + '/src/fwupdate.pug', // => dist/about.html
                    filename: 'fwupdate.html',
                    data: { title: 'Firmware' },
                },
            ],
            js: {
                // JS output filename
                filename: 'index.js',
                // JS output path
            },
            // css: {
            //     // CSS output filename
            //     filename: '[name].css',
            // },
            preprocessor: 'pug',
        }),
        new CompressionPlugin({
            filename: '[base].gz',
            test: /\.(js|css|png|svg)$/,
            minRatio: 0.8,
            algorithm: 'gzip',
        }),
    ],
    resolve: {
        extensions: ['*', '.js', '.jsx']
    },
    devServer: {
        historyApiFallback: true,
    },
};

