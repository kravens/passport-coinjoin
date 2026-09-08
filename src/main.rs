// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

mod coinjoin;
mod theme;
mod transport;

use slint_keyos_platform::app_ui2;

app_ui2!("Coinjoin Signer");

fn app_main(_cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);

    theme::init(&ui);
    coinjoin::init(&ui);

    ui.run().expect("UI running");
}
