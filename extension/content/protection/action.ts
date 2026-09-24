type DetectionStatus =
  | "SAFE"
  | "SUSPICIOUS"
  | "DANGEROUS";

function getProtectionAction(
  status: DetectionStatus,
): ProtectionAction {
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
