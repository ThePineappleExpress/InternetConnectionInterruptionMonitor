#!/usr/bin/env python3
# Internet Connection Interruption Monitor
# Copyright (C) 2026 ThePineappleExpress and contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Entry point for the Internet Connection Interruption Monitor."""

from monitor import InternetMonitor

if __name__ == "__main__":
    monitor = InternetMonitor()
    monitor.run()
