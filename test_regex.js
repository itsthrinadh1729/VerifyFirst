const URL_TEXT_PATTERN = /https?:\/\/[^\s<>\"'\u200B-\u200D\uFEFF\u00A0]+/gi;
const urls = [
  'http://192.0.2.146/login/secure)(http://192.0.2.146/login/secure', 
  'http://192.0.2.146/login/secure](http://192.0.2.146/login/secure', 
  'https://example.com/path_(test)', 
  'https://example.com/page[1]', 
  'https://www.google.com10:25', 
  'http://192.0.2.146:8080/login',
  '(see https://example.com/page)',
  'http://example.com/a10:20'
]; 

for(let u of urls) { 
  console.log('---', u); 
  let m; 
  URL_TEXT_PATTERN.lastIndex = 0;
  while(m = URL_TEXT_PATTERN.exec(u)) {
    // Split adjacent URLs concatenated by WhatsApp punctuation
    const spaced = m[0].replace(/([)\](]+)(https?:\/\/)/gi, "$1 $2");
    const pieces = spaced.split(" ");
    
    for (let piece of pieces) {
      // Clean leading brackets/parens (from splitting)
      let urlStr = piece.replace(/^[)\](]+/, "");
      
      // Clean trailing punctuation, respecting balanced brackets
      while (/[.,;:!?\)\]\(\[]+$/.test(urlStr)) {
          const lastChar = urlStr.slice(-1);
          
          if (lastChar === ')') {
            const openCount = (urlStr.match(/\(/g) || []).length;
            const closeCount = (urlStr.match(/\)/g) || []).length;
            if (openCount >= closeCount) {
              break; 
            }
          } else if (lastChar === ']') {
            const openCount = (urlStr.match(/\[/g) || []).length;
            const closeCount = (urlStr.match(/\]/g) || []).length;
            if (openCount >= closeCount) {
              break; 
            }
          } else if (lastChar === '(' || lastChar === '[') {
              // Always strip trailing opening brackets (e.g. at the boundary `)(`)
          } else {
              // For standard punctuation like .,;!? we don't have balance logic, just strip
          }
          
          urlStr = urlStr.slice(0, -1);
      }
      
      console.log('=>', urlStr);
    }
  } 
}
