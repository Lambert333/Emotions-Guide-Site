import { useState, useEffect } from "react";
import { Menu } from "lucide-react";
import { BrowserRouter as Router, Routes, Route, Link } from "react-router-dom";
import HomePage from "./pages/HomePage";
import AboutPage from "./pages/AboutPage";
import AuthPage from "./pages/AuthPage";
import ProfilePage from "./pages/ProfilePage";
import TestsPage from "./pages/TestsPage";
import ChartsPage from "./pages/ChartsPage";
import AIPsychologistPage from "./pages/AIPsychologistPage";
import RelaxationPage from "./pages/RelaxationPage";
import Navigation from "./components/Navigation";
import ProtectedRoute from "./components/ProtectedRoute";
import Footer from "./components/Footer";

function App() {
  const [collapsed, setCollapsed] = useState(false);
  const [isMobileOpen, setIsMobileOpen] = useState(false);
  const [isMobile, setIsMobile] = useState(false);

  useEffect(() => {
    const checkMobile = () => {
      setIsMobile(window.innerWidth <= 768);
    };

    checkMobile();
    window.addEventListener("resize", checkMobile);

    return () => window.removeEventListener("resize", checkMobile);
  }, []);

  const toggleSidebar = () => {
    if (isMobile) {
      setIsMobileOpen(!isMobileOpen);
    } else {
      setCollapsed(!collapsed);
    }
  };

  const closeMobileSidebar = () => {
    if (isMobile) {
      setIsMobileOpen(false);
    }
  };

  const handleOverlayClick = () => {
    if (isMobile) {
      setIsMobileOpen(false);
    }
  };

  // Determine sidebar width based on state
  const sidebarWidth = collapsed ? "60px" : "250px";

  return (
    <Router>
      <div className="App">
        {/* Fixed Top Header */}
        <header
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            height: "60px",
            backgroundColor: "var(--white)",
            borderBottom: "1px solid #e0e0e0",
            zIndex: 999,
            display: "flex",
            alignItems: "center",
            padding: "0 20px",
          }}
        >
          <div
            style={{
              marginLeft: isMobile ? "0" : sidebarWidth,
              display: "flex",
              alignItems: "center",
              width: "100%",
              justifyContent: "space-between",
              transition: "margin-left 0.3s ease",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "20px" }}>
              <button
                onClick={toggleSidebar}
                style={{
                  background: "none",
                  border: "none",
                  cursor: "pointer",
                  padding: "8px",
                  color: "var(--text-color)",
                }}
              >
                <Menu size={24} />
              </button>
              <Link
                to="/"
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "12px",
                  textDecoration: "none",
                  color: "inherit",
                }}
              >
                <img
                  src="/logo.png"
                  alt="Логотип Эмоции Гид"
                  style={{
                    height: "40px",
                    width: "40px",
                    objectFit: "contain",
                  }}
                />
                <h1
                  style={{
                    margin: 0,
                    color: "var(--primary-blue)",
                    fontSize: "24px",
                  }}
                >
                  Эмоции Гид
                </h1>
              </Link>
            </div>
          </div>
        </header>

        {/* Main Content */}
        <main
          style={{
            marginLeft: isMobile ? "0" : sidebarWidth,
            marginTop: "60px",
            minHeight: isMobile ? "calc(100vh - 60px)" : "calc(100vh - 60px)",
            padding: "20px",
            transition: "margin-left 0.3s ease",
            overflowY: "auto",
            WebkitOverflowScrolling: "touch",
          }}
        >
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/about" element={<AboutPage />} />
            <Route path="/auth" element={<AuthPage />} />
            <Route
              path="/relaxation"
              element={
                <ProtectedRoute>
                  <RelaxationPage />
                </ProtectedRoute>
              }
            />

            {/* Protected Routes */}
            <Route
              path="/profile"
              element={
                <ProtectedRoute>
                  <ProfilePage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/tests"
              element={
                <ProtectedRoute>
                  <TestsPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/charts"
              element={
                <ProtectedRoute>
                  <ChartsPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/ai-psychologist"
              element={
                <ProtectedRoute>
                  <AIPsychologistPage />
                </ProtectedRoute>
              }
            />
          </Routes>
        </main>

        <Footer />

        {/* Mobile Overlay */}
        {isMobile && isMobileOpen && (
          <div
            className="mobile-overlay active"
            onClick={handleOverlayClick}
            style={{
              position: "fixed",
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              backgroundColor: "rgba(0, 0, 0, 0.5)",
              zIndex: 999,
              display: "block",
              touchAction: "none" /* Prevent scrolling on overlay */,
            }}
          />
        )}

        <Navigation
          collapsed={collapsed}
          isMobileOpen={isMobileOpen}
          onNavigate={closeMobileSidebar}
        />
      </div>
    </Router>
  );
}

export default App;
