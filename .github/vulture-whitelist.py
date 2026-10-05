# Names vulture reports as unused that are not.
#
# Vulture reads the code without running it, so it cannot see a name that is
# only ever WRITTEN here and READ by somebody else's library. Everything below
# is that case - an attribute the standard library or Flask reads back out of
# an object we hand it. None of these can be deleted.
#
# Flask's own registration decorators (@app.route and friends) are handled on
# the command line with --ignore-decorators instead, in the workflow that runs
# this file; without it, all 43 route handlers are reported.
#
# Add to this file only when a report is genuinely a false positive, and say
# which library reads the name. A name parked here to silence a real finding
# is worse than no check at all.

row_factory      # sqlite3.Connection.row_factory - sqlite3 reads it per query
permanent        # flask.session.permanent - Flask reads it to apply the lifetime
compress_type    # zipfile.ZipInfo.compress_type - zipfile reads it when writing
