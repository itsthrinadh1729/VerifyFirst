"use strict";
function getProtectionAction(status) {
    switch (status) {
        case "SAFE":
            return "ALLOW";
        case "SUSPICIOUS":
            return "WARN";
        case "DANGEROUS":
            return "BLOCK";
        default:
            return "BLOCK";
    }
}
