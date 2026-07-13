import argparse

from keepassxc_proxy_client import commands, keystore


def _add_file_arg(p, default):
    p.add_argument(
        "--file",
        "-f",
        default=default,
        help="Path to the keystore JSON file. Defaults to %(default)s.",
    )


def _add_id_arg(p):
    p.add_argument(
        "--id",
        "-i",
        dest="id",
        default=None,
        help=(
            "Association id to use. If omitted, all stored associations are tried "
            "in turn until one authenticates successfully."
        ),
    )


def build_parser():
    default_keystore = keystore.default_path()
    parser = argparse.ArgumentParser(
        prog="keepassxc_proxy_client",
        description="Client for the KeePassXC Browser Integration protocol.",
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    p_create = sub.add_parser(
        "create",
        help="Create a new association with a running KeePassXC instance.",
        description=(
            "Connects to a locally running keepassxc instance and creates a new "
            "association (this will prompt a dialogue from KeePassXC). Without "
            "--save the association is printed to stdout as JSON. With --save it "
            "is persisted to the keystore file under the id returned by "
            "KeePassXC."
        ),
    )
    _add_file_arg(p_create, default_keystore)
    p_create.add_argument(
        "--save",
        "-s",
        action="store_true",
        help="Persist the new association to the keystore file instead of printing it.",
    )
    p_create.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing association with the same id (use with --save).",
    )
    p_create.set_defaults(func=commands.cmd_create)

    p_get = sub.add_parser(
        "get",
        help="Get the first password for an entry matched by URL.",
        description=(
            "Reads keepassxc associations from the keystore file and attempts "
            "to get the first password for <url>. Each stored association is "
            "tried until one authenticates. Exits with 1 if no association "
            "authenticates or no logins are found."
        ),
    )
    _add_file_arg(p_get, default_keystore)
    _add_id_arg(p_get)
    p_get.add_argument("url", help="URL to look up.")
    p_get.set_defaults(func=commands.cmd_get)

    p_totp = sub.add_parser(
        "totp",
        help="Get the current TOTP for an entry UUID.",
        description=(
            "Reads keepassxc associations from the keystore file and attempts "
            "to get the current TOTP for <uuid>. Each stored association is "
            "tried until one authenticates. Exits with 1 if no association "
            "authenticates or no TOTP is found."
        ),
    )
    _add_file_arg(p_totp, default_keystore)
    _add_id_arg(p_totp)
    p_totp.add_argument("uuid", help="Entry UUID.")
    p_totp.set_defaults(func=commands.cmd_totp)

    p_unlock = sub.add_parser(
        "unlock",
        help="Ask KeePassXC to prompt the user to unlock a database.",
        description=(
            "Causes a running KeePassXC instance to launch a dialogue window to "
            "allow the user to unlock a locked database. If the database is "
            "already unlocked it has no effect."
        ),
    )
    _add_file_arg(p_unlock, default_keystore)
    _add_id_arg(p_unlock)
    p_unlock.set_defaults(func=commands.cmd_unlock)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
