"""
cli.py
Click-based CLI for the password manager. Implements 'init' command.
"""
import click
from getpass import getpass
from vault import Vault, VaultError
from crypto_utils import generate_password
import os

@click.group()
def cli():
    """Personal Encrypted Password Manager CLI."""
    pass

@cli.command()
def init():
    """
    Initialise a new encrypted password vault.
    """
    password = getpass("Set master password: ")
    confirm = getpass("Confirm master password: ")
    if password != confirm:
        click.echo("Passwords do not match.")
        return
    try:
        vault = Vault()
        vault.initialise(password)
        click.echo("Vault initialised and encrypted successfully.")
    except VaultError as e:
        click.echo(f"Error: {e}")

@cli.command()
def add():
    """
    Add a new password entry to the vault.
    """
    from getpass import getpass
    service = click.prompt("Service name", type=str)
    username = click.prompt("Username", type=str)

    # Ask user if they want to generate a password or enter manually
    use_generate = click.confirm("Do you want to generate a password?", default=False)
    if use_generate:
        length = click.prompt("Password length", type=int, default=16)
        use_letters = click.confirm("Include letters?", default=True)
        use_numbers = click.confirm("Include numbers?", default=True)
        use_symbols = click.confirm("Include symbols?", default=True)
        try:
            password = generate_password(length, use_letters, use_numbers, use_symbols)
            click.echo(f"Generated password: {password}")
            click.echo("(Make sure to copy/save this password!)")
        except ValueError as e:
            click.echo(f"Error: {e}")
            return
    else:
        password = getpass("Password: ")

    notes = click.prompt("Notes", type=str, default="", show_default=False)
    master_password = getpass("Master password to unlock vault: ")
    try:
        vault = Vault()
        vault.unlock(master_password)
        vault.add_entry(service, username, password, notes)
        click.echo(f"Entry for '{service}' added successfully.")
        vault.lock()
    except VaultError as e:
        click.echo(f"Error: {e}")

@cli.command()
def get():
    """
    Retrieve and decrypt a password entry by service name.
    """
    from getpass import getpass
    service = click.prompt("Service name", type=str)
    master_password = getpass("Master password to unlock vault: ")
    try:
        vault = Vault()
        vault.unlock(master_password)
        entry = vault.get_entry(service)
        click.echo(f"Service: {service}")
        click.echo(f"Username: {entry['username']}")
        click.echo(f"Password: {entry['password']}")
        if entry.get('notes'):
            click.echo(f"Notes: {entry['notes']}")
        vault.lock()
    except VaultError as e:
        click.echo(f"Error: {e}")

@cli.command()
def list():
    """
    List all stored service names in the vault (no passwords shown).
    """
    from getpass import getpass
    master_password = getpass("Master password to unlock vault: ")
    try:
        vault = Vault()
        vault.unlock(master_password)
        services = vault.list_services()
        if not services:
            click.echo("No entries found in the vault.")
        else:
            click.echo("Stored services:")
            for service in services:
                click.echo(f"- {service}")
        vault.lock()
    except VaultError as e:
        click.echo(f"Error: {e}")

@cli.command()
def update():
    """
    Update an existing password entry in the vault.
    """
    from getpass import getpass
    service = click.prompt("Service name to update", type=str)
    master_password = getpass("Master password to unlock vault: ")
    try:
        vault = Vault()
        vault.unlock(master_password)
        entry = vault.get_entry(service)
        click.echo("Leave fields blank to keep current values.")
        username = click.prompt("New username", default=entry['username'], show_default=False)
        password = getpass("New password (leave blank to keep current): ")
        notes = click.prompt("New notes", default=entry.get('notes', ''), show_default=False)
        # Only update fields that changed
        username = username if username != entry['username'] else None
        password = password if password else None
        notes = notes if notes != entry.get('notes', '') else None
        if not any([username, password, notes]):
            click.echo("No changes provided.")
        else:
            vault.update_entry(service, username=username, password=password, notes=notes)
            click.echo(f"Entry for '{service}' updated successfully.")
        vault.lock()
    except VaultError as e:
        click.echo(f"Error: {e}")

@cli.command()
def delete():
    """
    Delete an existing password entry from the vault by service name.
    """
    from getpass import getpass
    service = click.prompt("Service name to delete", type=str)
    master_password = getpass("Master password to unlock vault: ")
    confirm = click.confirm(f"Are you sure you want to delete the entry for '{service}'?", default=False)
    if not confirm:
        click.echo("Delete operation cancelled.")
        return
    try:
        vault = Vault()
        vault.unlock(master_password)
        vault.delete_entry(service)
        click.echo(f"Entry for '{service}' deleted successfully.")
        vault.lock()
    except VaultError as e:
        click.echo(f"Error: {e}")

@cli.command()
def export():
    """
    Export the entire encrypted vault as a single file.
    """
    import shutil
    export_path = click.prompt("Export file path", type=str)
    if not os.path.exists(Vault().path):
        click.echo("No vault file found to export.")
        return
    if os.path.exists(export_path):
        overwrite = click.confirm(f"File '{export_path}' already exists. Overwrite?", default=False)
        if not overwrite:
            click.echo("Export cancelled.")
            return
    try:
        shutil.copy2(Vault().path, export_path)
        click.echo(f"Vault exported to '{export_path}'.")
    except Exception as e:
        click.echo(f"Error exporting vault: {e}")

@cli.command()
def import_():
    """
    Import an encrypted vault file, replacing the current vault.
    """
    import shutil
    import_path = click.prompt("Import file path", type=str)
    if not os.path.exists(import_path):
        click.echo(f"File '{import_path}' does not exist.")
        return
    if os.path.exists(Vault().path):
        overwrite = click.confirm(f"A vault already exists at '{Vault().path}'. Overwrite?", default=False)
        if not overwrite:
            click.echo("Import cancelled.")
            return
    try:
        shutil.copy2(import_path, Vault().path)
        click.echo(f"Vault imported from '{import_path}'.")
    except Exception as e:
        click.echo(f"Error importing vault: {e}")

@cli.command()
@click.option('--length', default=16, help='Length of the password.')
@click.option('--no-letters', 'use_letters', flag_value=False, default=True, help="Don't include letters.")
@click.option('--no-numbers', 'use_numbers', flag_value=False, default=True, help="Don't include numbers.")
@click.option('--no-symbols', 'use_symbols', flag_value=False, default=True, help="Don't include symbols.")
def generate(length, use_letters, use_numbers, use_symbols):
    """Generate a secure password."""
    try:
        password = generate_password(length, use_letters, use_numbers, use_symbols)
        click.echo(f"Generated password: {password}")
    except ValueError as e:
        click.echo(f"Error: {e}")

# Alias for click: 'import' is a reserved word in Python
cli.add_command(import_, name="import")

if __name__ == "__main__":
    cli() 