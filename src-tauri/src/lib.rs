//! Platform split: Linux is a thin client of the system service (`linux`);
//! Windows keeps the embedded proxy runtime and tray (`embedded`).
mod diagnostic_export;
mod embedded;
#[cfg(target_os = "linux")]
mod linux;

pub fn run() {
    #[cfg(target_os = "linux")]
    {
        // Match the packaged desktop entry on X11 as well as the GTK app ID on
        // Wayland. Set the class before Tauri creates any windows.
        gtk::init().expect("HomeProxy nedokázal inicializovat GTK");
        gtk::gdk::set_program_class("cz.klidnasit.desktop");
        gtk::Window::set_default_icon_name("klidna-sit");
        linux::run();
    }
    #[cfg(not(target_os = "linux"))]
    embedded::run();
}
