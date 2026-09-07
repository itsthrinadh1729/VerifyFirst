const URL_TEXT_PATTERN = /https?:\/\/[^\s<>"'\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF\u00A0]+/gi;
const text = "http://192.168.1.1/admin";
const match = URL_TEXT_PATTERN.exec(text);
console.log("Match:", match);
