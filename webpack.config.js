const webpack = require('webpack')

module.exports = {
  entry: ['@babel/polyfill', './src/index.js'],
  devtool: 'source-map',
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /(node_modules|bower_components)/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: ['@babel/preset-env'],
            plugins: [
              '@babel/plugin-syntax-dynamic-import',
              [
                'transform-imports',
                {
                  lodash: {
                    transform: 'lodash/fp/${member}',
                    preventFullImport: true
                  }
                }
              ]
            ]
          }
        }
      }
    ]
  },
  devServer: {
    contentBase: './dist',
    hot: true
  },
  plugins: [new webpack.HotModuleReplacementPlugin()]
}
