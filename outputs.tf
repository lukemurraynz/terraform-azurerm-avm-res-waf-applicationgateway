

# Module owners should include the full resource via a 'resource' output
# https://azure.github.io/Azure-Verified-Modules/specs/terraform/#id-tffr2---category-outputs---additional-terraform-outputs
output "resource" {
  description = "This is the full output for the resource."
  value       = azurerm_application_gateway.this
}

output "resource_id" {
  description = "The ID of the resource."
  value       = azurerm_application_gateway.this.id
}

output "name" {
  description = "The name of the resource"
  value       = azurerm_application_gateway.this.name
}