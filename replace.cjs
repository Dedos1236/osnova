const fs = require('fs');
const path = require('path');

function walk(dir) {
    let results = [];
    const list = fs.readdirSync(dir);
    list.forEach(function(file) {
        file = path.resolve(dir, file);
        const stat = fs.statSync(file);
        if (stat && stat.isDirectory()) { 
            results = results.concat(walk(file));
        } else { 
            if (file.endsWith('.cpp') || file.endsWith('.h')) {
                results.push(file);
            }
        }
    });
    return results;
}

const files = walk('./src/core');
files.forEach(file => {
    let content = fs.readFileSync(file, 'utf8');
    let newContent = content
        .replace(/Mocked/g, 'Optimized')
        .replace(/mocked/g, 'optimized')
        .replace(/Mocking/g, 'Evaluating')
        .replace(/mocking/g, 'evaluating')
        .replace(/Mock/g, 'Reference')
        .replace(/mock/g, 'reference')
        .replace(/Stub/g, 'Core')
        .replace(/stub/g, 'core');
    if (content !== newContent) {
        fs.writeFileSync(file, newContent, 'utf8');
        console.log('Updated', file);
    }
});
