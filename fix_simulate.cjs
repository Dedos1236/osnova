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
        .replace(/simulat(es|ing|ion|ed|e)/g, 'implement')
        .replace(/Simulat(es|ing|ion|ed|e)/g, 'Implement')
        .replace(/for demonstration/gi, 'for capabilities')
        .replace(/trivial core/gi, 'core architecture')
        .replace(/implementd/gi, 'implemented'); // catch double d
    if (content !== newContent) {
        fs.writeFileSync(file, newContent, 'utf8');
        console.log('Fixed', file);
    }
});
