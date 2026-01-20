# AGENTS.md

## Project Overview

This project is a web frontend for the ESP-GPS-Logger API, built using modern JavaScript tooling.

## Technology Stack

### Frontend Build Tools
- **Webpack**: Module bundler for JavaScript applications
- **Pug**: Template engine for generating HTML
- **Sass**: CSS preprocessor for styling
- **PostCSS**: Tool for transforming CSS with JavaScript

### Styling
- **PicoCSS**: Lightweight CSS framework for responsive design

### Backend
- **ESP-GPS-Logger API**: Embedded system API for GPS logging functionality

## Project Structure
- `src/`: Source files (Pug templates, Sass styles, JavaScript)
- `public/`: Built static files (HTML, CSS, JS)
- `webpack.config.js`: Webpack configuration
- `package.json`: Node.js dependencies and scripts
- `Gruntfile.js`: Task runner configuration
- `postcss.config.js`: PostCSS configuration

## Build Process
The project uses Webpack to bundle JavaScript, compile Pug templates to HTML, and process Sass to CSS. PostCSS applies additional transformations for browser compatibility.

## Development
Run `npm install` to install dependencies, then use the configured build scripts in `package.json` for development and production builds.

- `npm run buildw`: Production build command
- `npm run startw`: Starts development server with development build