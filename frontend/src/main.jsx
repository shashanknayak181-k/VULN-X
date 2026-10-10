import React, {
  useState,
  useEffect,
  createContext,
  useContext,
} from "react";

import {
  BrowserRouter,
  Routes,
  Route,
  Link,
  Navigate,
  useNavigate,
  useParams,
} from "react-router-dom";

import axios from "axios";

import {
  Shield,
  LayoutDashboard,
  ScanLine,
  History,
  FileText,
  LogOut,
  User,
  Settings,
  ShieldCheck,
  AlertTriangle,
  Activity,
  Menu,
  X,
  Play,
  ArrowRight,
  Download,
  ExternalLink,
  Globe,
} from "lucide-react";

import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

import "./styles.css";
import "./threat-intel.css";


/* =========================================================
   API
========================================================= */

const API = "http://localhost:8000";


/* =========================================================
   AUTH CONTEXT
========================================================= */

const Auth = createContext(null);

function useAuth() {
  return useContext(Auth);
}

function Provider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem("vulnx_token");

    if (!token) {
      setLoading(false);
      return;
    }

    axios
      .get(`${API}/api/auth/me`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      })
      .then((response) => {
        setUser(response.data);
      })
      .catch(() => {
        localStorage.removeItem("vulnx_token");
        setUser(null);
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  const login = (data) => {
    localStorage.setItem("vulnx_token", data.token);
    setUser(data.user);
  };

  const logout = () => {
    localStorage.removeItem("vulnx_token");
    setUser(null);
  };

  return (
    <Auth.Provider
      value={{
        user,
        login,
        logout,
        loading,
      }}
    >
      {children}
    </Auth.Provider>
  );
}


/* =========================================================
   AUTH HEADERS
========================================================= */

function authHeaders() {
  const token = localStorage.getItem("vulnx_token");

  return {
    Authorization: `Bearer ${token}`,
  };
}


/* =========================================================
   PROTECTED ROUTE
========================================================= */

function Protected({ children }) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="boot">
        INITIALIZING VULN-X...
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return children;
}


/* =========================================================
   SIDEBAR
========================================================= */

function Nav() {
  const { logout } = useAuth();

  const [open, setOpen] = useState(false);

  const items = [
    ["/dashboard", "Dashboard", LayoutDashboard],
    ["/scanner", "New Scan", ScanLine],
    ["/history", "Scan History", History],
    ["/reports", "Reports", FileText],
    ["/security-center", "Security Center", ShieldCheck],
    ["/profile", "Profile", User],
    ["/settings", "Settings", Settings],
  ];

  return (
    <>
      <button
        className="mobile-menu"
        onClick={() => setOpen(!open)}
      >
        {open ? <X /> : <Menu />}
      </button>

      <aside className={`side ${open ? "open" : ""}`}>

        <div className="brand">
          <Shield />
          <span>
            VULN-<b>X</b>
          </span>
        </div>

        <div className="side-status">
          ● SYSTEM ONLINE
        </div>

        {items.map(([path, name, Icon]) => (
          <Link
            key={path}
            to={path}
            className="nav"
            onClick={() => setOpen(false)}
          >
            <Icon size={18} />
            {name}
          </Link>
        ))}

        <button
          className="logout"
          onClick={logout}
        >
          <LogOut size={18} />
          Logout
        </button>

      </aside>
    </>
  );
}


/* =========================================================
   SHELL
========================================================= */

function Shell({ children }) {
  return (
    <div>
      <Nav />

      <main className="main">
        {children}
      </main>
    </div>
  );
}


/* =========================================================
   LANDING PAGE
========================================================= */

function Landing() {
  return (
    <div className="landing">

      <div className="grid" />

      <header className="public-nav">

        <div className="brand">
          <Shield />
          VULN-<b>X</b>
        </div>

        <div>
          <Link
            to="/login"
            className="ghost"
          >
            SIGN IN
          </Link>

          <Link
            to="/register"
            className="red-btn"
          >
            CREATE ACCOUNT
          </Link>
        </div>

      </header>


      <section className="hero">

        <div className="eyebrow">
          ● DEFENSIVE SECURITY PLATFORM
        </div>

        <h1>
          SCAN.
          <br />
          <span>DETECT.</span>
          <br />
          SECURE.
        </h1>

        <p>
          Identify common security weaknesses with a
          safe, non-destructive vulnerability assessment
          workflow.
        </p>

        <div className="hero-actions">

          <Link
            className="red-btn big"
            to="/register"
          >
            START SCANNING
            <ArrowRight />
          </Link>

          <Link
            className="ghost big"
            to="/login"
          >
            SIGN IN
          </Link>

        </div>


        <div className="terminal">

          <div className="term-top">
            <span>VULN-X TERMINAL</span>
            <span>● ONLINE</span>
          </div>

          <p>
            &gt; initializing VULN-X...
          </p>

          <p>
            &gt; loading security modules...
          </p>

          <p className="ok">
            &gt; scanner engine online
          </p>

          <p className="ok">
            &gt; vulnerability engine online
          </p>

          <p>
            &gt; threat analysis ready
            <span className="cursor">_</span>
          </p>

        </div>

      </section>


      <section className="features">

        {[
          "PORT SCANNING",
          "CONFIGURATION ANALYSIS",
          "SOFTWARE DETECTION",
          "VULNERABILITY ANALYSIS",
          "RISK SCORING",
          "SECURITY REPORTS",
        ].map((feature, index) => (

          <div
            className="feature"
            key={feature}
          >

            <span>
              0{index + 1}
            </span>

            <h3>{feature}</h3>

            <p>
              Focused defensive analysis with clear
              evidence and remediation guidance.
            </p>

          </div>

        ))}

      </section>

    </div>
  );
}


/* =========================================================
   LOGIN / REGISTER
========================================================= */

function AuthPage({ register = false }) {

  const { login } = useAuth();

  const navigate = useNavigate();

  const [form, setForm] = useState({
    name: "",
    username: "",
    email: "",
    password: "",
    confirm_password: "",
  });

  const [error, setError] = useState("");

  const [busy, setBusy] = useState(false);


  async function submit(event) {

    event.preventDefault();

    setError("");

    setBusy(true);

    try {

      const body = register
        ? form
        : {
          identifier: form.email,
          password: form.password,
        };

      const response = await axios.post(
        register
          ? `${API}/api/auth/register`
          : `${API}/api/auth/login`,
        body
      );

      login(response.data);

      navigate("/dashboard");

    } catch (error) {

      setError(
        error.response?.data?.detail ||
        "Request failed."
      );

    } finally {

      setBusy(false);

    }
  }


  return (
    <div className="auth">

      <div className="auth-card">

        <div className="brand center">
          <Shield />
          VULN-<b>X</b>
        </div>

        <div className="term-mini">
          &gt; authentication required
          <br />
          &gt; establishing secure session...
          <br />
          &gt; awaiting credentials_
        </div>

        <h1>
          {register
            ? "CREATE SECURITY ACCOUNT"
            : "AUTHENTICATE"}
        </h1>


        {error && (
          <div className="error">
            {error}
          </div>
        )}


        <form onSubmit={submit}>

          {register && (
            <>
              <input
                placeholder="Full Name"
                required
                value={form.name}
                onChange={(event) =>
                  setForm({
                    ...form,
                    name: event.target.value,
                  })
                }
              />

              <input
                placeholder="Username"
                required
                value={form.username}
                onChange={(event) =>
                  setForm({
                    ...form,
                    username: event.target.value,
                  })
                }
              />
            </>
          )}


          <input
            placeholder={
              register
                ? "Email"
                : "Email or Username"
            }
            required
            value={form.email}
            onChange={(event) =>
              setForm({
                ...form,
                email: event.target.value,
              })
            }
          />


          <input
            type="password"
            placeholder="Password"
            required
            value={form.password}
            onChange={(event) =>
              setForm({
                ...form,
                password: event.target.value,
              })
            }
          />


          {register && (
            <input
              type="password"
              placeholder="Confirm Password"
              required
              value={form.confirm_password}
              onChange={(event) =>
                setForm({
                  ...form,
                  confirm_password: event.target.value,
                })
              }
            />
          )}


          <button
            className="red-btn submit"
            disabled={busy}
          >
            {busy
              ? "AUTHENTICATING..."
              : register
                ? "CREATE SECURITY ACCOUNT"
                : "LOGIN"}
          </button>

        </form>


        <p className="switch">

          {register
            ? "Already have an account? "
            : "Need an account? "}

          <Link
            to={
              register
                ? "/login"
                : "/register"
            }
          >
            {register
              ? "Sign in"
              : "Sign up"}
          </Link>

        </p>

      </div>

    </div>
  );
}


/* =========================================================
   DASHBOARD
========================================================= */

function Dashboard() {

  const { user } = useAuth();

  const [scans, setScans] = useState([]);

  useEffect(() => {
    loadScans();
  }, []);


  async function loadScans() {

    try {

      const response = await axios.get(
        `${API}/api/scans`,
        {
          headers: authHeaders(),
        }
      );

      setScans(response.data);

    } catch (error) {

      console.error(
        "Unable to load scans:",
        error
      );

    }
  }


  const findings =
    scans.flatMap(
      (scan) => scan.findings || []
    );


  const high =
    findings.filter(
      (finding) =>
        finding.severity === "HIGH" ||
        finding.severity === "CRITICAL"
    ).length;


  const score =
    scans[0]?.security_score ?? 100;


  return (
    <Shell>

      <PageTitle
        title="SECURITY OVERVIEW"
        sub={`Welcome back, ${user?.name || "operator"
          }.`}
      />


      <div className="stats">

        <Stat
          n={scans.length}
          l="TOTAL SCANS"
          icon={ScanLine}
        />

        <Stat
          n={
            findings.filter(
              (finding) =>
                finding.severity === "CRITICAL"
            ).length
          }
          l="CRITICAL FINDINGS"
          icon={AlertTriangle}
        />

        <Stat
          n={high}
          l="HIGH RISK"
          icon={Activity}
        />

        <Stat
          n={score}
          l="SECURITY SCORE"
          icon={ShieldCheck}
        />

      </div>


      <div className="dashboard-grid">

        <div className="panel score-panel">

          <div className="panel-head">
            SECURITY STATUS
            <span>LIVE</span>
          </div>

          <div className="score">
            {score}
            <small>/100</small>
          </div>

          <div className="risk">

            {score >= 90
              ? "SECURE"
              : score >= 75
                ? "LOW RISK"
                : score >= 50
                  ? "MODERATE RISK"
                  : score >= 25
                    ? "HIGH RISK"
                    : "CRITICAL"}

          </div>

          <div className="bar">
            <i
              style={{
                width: `${score}%`,
              }}
            />
          </div>

        </div>


        <div className="panel">

          <div className="panel-head">

            RECENT SCANS

            <Link to="/history">
              VIEW ALL
            </Link>

          </div>


          {scans.slice(0, 5).map((scan) => (

            <Link
              className="scan-row"
              to={`/scan/${scan.id}`}
              key={scan.id}
            >

              <span>

                <b>{scan.target}</b>

                <small>
                  {scan.scan_type} ·{" "}
                  {new Date(
                    scan.completed_at
                  ).toLocaleString()}
                </small>

              </span>

              <strong>
                {scan.security_score}
              </strong>

            </Link>

          ))}


          {!scans.length && <Empty />}

        </div>

      </div>


      <div className="panel recommendations">

        <div className="panel-head">
          SECURITY RECOMMENDATIONS
        </div>

        <p>
          ▸ Run a demo scan for your presentation.
        </p>

        <p>
          ▸ Review exposed services and unnecessary ports.
        </p>

        <p>
          ▸ Configure modern HTTP security headers.
        </p>

      </div>

    </Shell>
  );
}


/* =========================================================
   STAT
========================================================= */

function Stat({ n, l, icon: Icon }) {

  return (
    <div className="stat">

      <Icon />

      <small>{l}</small>

      <strong>{n}</strong>

    </div>
  );
}


/* =========================================================
   PAGE TITLE
========================================================= */

function PageTitle({
  title,
  sub,
  action,
}) {

  return (
    <div className="page-title">

      <div>

        <div className="eyebrow">
          {title}
        </div>

        <h1>{sub}</h1>

      </div>

      {action}

    </div>
  );
}


/* =========================================================
   EMPTY
========================================================= */

function Empty() {

  return (
    <div className="empty">
      No scans yet.
    </div>
  );
}


/* =========================================================
   SCANNER
========================================================= */

function Scanner() {

  const navigate = useNavigate();

  const [target, setTarget] =
    useState("localhost");

  const [type, setType] =
    useState("standard");

  const [authorized, setAuthorized] =
    useState(false);

  const [busy, setBusy] =
    useState(false);

  const [logs, setLogs] =
    useState([]);

  const [error, setError] =
    useState("");


  async function demoScan() {

    setBusy(true);

    setLogs([
      "initializing demo engine...",
      "loading simulated target...",
      "checking ports...",
      "analyzing security headers...",
      "calculating risk score...",
    ]);

    try {

      const response =
        await axios.post(
          `${API}/api/scans/demo`,
          {},
          {
            headers: authHeaders(),
          }
        );

      navigate(
        `/scan/${response.data.id}`
      );

    } catch (error) {

      setError("Demo scan failed.");

      setBusy(false);
    }
  }


  async function startScan() {

    setError("");

    if (!authorized) {
      return;
    }

    setBusy(true);

    setLogs([
      "target validated",
      "authorization confirmed",
      "scanner initialized",
      "checking network ports...",
      "checking HTTP configuration...",
      "detecting server information...",
      "calculating risk score...",
    ]);


    try {

      const response =
        await axios.post(
          `${API}/api/scans`,
          {
            target,
            scan_type: type,
            authorized,
          },
          {
            headers: authHeaders(),
          }
        );

      navigate(
        `/scan/${response.data.id}`
      );

    } catch (error) {

      setError(
        error.response?.data?.detail ||
        "Scan failed."
      );

      setBusy(false);
    }
  }


  return (
    <Shell>

      <PageTitle
        title="NEW SCAN"
        sub="Configure a defensive security assessment."
      />


      <div className="scanner-grid">

        <div className="panel form-panel">

          <label>
            TARGET

            <input
              value={target}
              onChange={(event) =>
                setTarget(event.target.value)
              }
              placeholder="example.com or localhost"
            />

          </label>


          <label>
            SCAN TYPE

            <select
              value={type}
              onChange={(event) =>
                setType(event.target.value)
              }
            >

              <option value="quick">
                Quick Scan
              </option>

              <option value="standard">
                Standard Scan
              </option>

              <option value="web">
                Web Security Scan
              </option>

            </select>

          </label>


          <label className="check">

            <input
              type="checkbox"
              checked={authorized}
              onChange={(event) =>
                setAuthorized(
                  event.target.checked
                )
              }
            />

            I confirm that I have authorization
            to scan this target.

          </label>


          {error && (
            <div className="error">
              {error}
            </div>
          )}


          <button
            className="red-btn submit"
            disabled={
              !authorized || busy
            }
            onClick={startScan}
          >

            <ScanLine />

            {busy
              ? "SCANNING..."
              : "START SECURITY SCAN"}

          </button>


          <button
            className="demo-btn"
            disabled={busy}
            onClick={demoScan}
          >

            <Play />

            RUN DEMO SCAN

          </button>

        </div>


        <div className="terminal big-terminal">

          <div className="term-top">

            <span>
              VULN-X SCANNER
            </span>

            <span>
              SAFE MODE
            </span>

          </div>


          {(logs.length
            ? logs
            : ["waiting for scan..."]
          ).map((log, index) => (

            <p
              key={index}
              className={
                log.includes("confirmed") ||
                  log.includes("initialized")
                  ? "ok"
                  : ""
              }
            >

              [{index < 3 ? "✓" : ">"}]{" "}
              {log}

            </p>

          ))}


          {busy && (
            <div className="scanline" />
          )}

        </div>

      </div>

    </Shell>
  );
}


/* =========================================================
   SCAN RESULTS
========================================================= */

function Scan({ id }) {

  const [data, setData] =
    useState(null);

  const [downloading, setDownloading] =
    useState(false);


  useEffect(() => {

    loadScan();

  }, [id]);


  async function loadScan() {

    try {

      const response =
        await axios.get(
          `${API}/api/scans/${id}`,
          {
            headers: authHeaders(),
          }
        );

      setData(response.data);

    } catch (error) {

      console.error(
        "Unable to load scan:",
        error
      );

    }
  }


  /* =======================================================
     PDF DOWNLOAD
  ======================================================= */

  async function downloadPDF() {

    if (!data) {
      return;
    }

    setDownloading(true);


    try {

      const response =
        await axios.get(
          `${API}/api/reports/${data.id}/pdf`,
          {
            headers: authHeaders(),
            responseType: "blob",
          }
        );


      const blob =
        new Blob(
          [response.data],
          {
            type: "application/pdf",
          }
        );


      const url =
        window.URL.createObjectURL(blob);


      const link =
        document.createElement("a");


      link.href = url;


      link.download =
        `VULN-X-Report-${data.id}.pdf`;


      document.body.appendChild(link);


      link.click();


      document.body.removeChild(link);


      window.URL.revokeObjectURL(url);

    } catch (error) {

      console.error(
        "PDF generation failed:",
        error
      );

      alert(
        "Unable to generate PDF report. Make sure the backend PDF endpoint is configured."
      );

    } finally {

      setDownloading(false);

    }
  }


  /* =======================================================
     CSV EXPORT (additional feature)
  ======================================================= */

  function exportCSV() {
    if (!data) return;

    const rows = [
      ["Section", "Target", "Scan Type", "Status", "Security Score", "Severity/State", "Name", "Details", "Evidence", "Recommendation"],
      ["Summary", data.target, data.scan_type, data.status, data.security_score, "", "", "", "", ""],
      ...(data.ports || []).map((port) => [
        "Port", data.target, data.scan_type, data.status, data.security_score,
        port.state, `${port.port}/${port.protocol}`, port.service || "", "", "",
      ]),
      ...(data.findings || []).map((finding) => [
        "Finding", data.target, data.scan_type, data.status, data.security_score,
        finding.severity, finding.title, finding.description, finding.evidence,
        finding.recommendation,
      ]),
    ];

    const escapeCell = (value) => {
      const text = String(value ?? "");
      return `"${text.replace(/"/g, '""')}"`;
    };
    const csv = rows.map((row) => row.map(escapeCell).join(",")).join("\r\n");
    const blob = new Blob(["\uFEFF", csv], { type: "text/csv;charset=utf-8;" });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `VULN-X-Scan-${data.id}.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  }

  /* =======================================================
     PRINT
  ======================================================= */

  function printReport() {

    window.print();

  }


  if (!data) {

    return (
      <Shell>

        <div className="boot">
          LOADING SCAN...
        </div>

      </Shell>
    );
  }


  const counts = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
  ]
    .map((severity) => ({
      name: severity,

      value:
        data.findings.filter(
          (finding) =>
            finding.severity === severity
        ).length,
    }))
    .filter(
      (item) => item.value > 0
    );


  const chartColors = [
    "#ff1e1e",
    "#d91e18",
    "#ff7a00",
    "#888888",
    "#555555",
  ];


  return (
    <Shell>

      <PageTitle
        title="SCAN RESULTS"
        sub={data.target}
        action={
          <div
            style={{
              display: "flex",
              gap: "8px",
              flexWrap: "wrap",
            }}
          >

            <button
              className="red-btn"
              onClick={downloadPDF}
              disabled={downloading}
            >

              <Download size={16} />

              {downloading
                ? "GENERATING..."
                : "DOWNLOAD PDF REPORT"}

            </button>


            <button
              className="demo-btn"
              onClick={exportCSV}
            >
              EXPORT CSV
            </button>

            <button
              className="demo-btn"
              onClick={printReport}
            >
              PRINT REPORT
            </button>

          </div>
        }
      />


      {/* ===================================================
          SCAN SUMMARY
      =================================================== */}

      <div className="result-top">

        <div className="score-box">

          <span>
            SECURITY SCORE
          </span>

          <b>
            {data.security_score}
          </b>

          <small>
            /100
          </small>

        </div>


        <div>

          <span>
            STATUS
          </span>

          <b className="oktxt">
            {data.status.toUpperCase()}
          </b>

        </div>


        <div>

          <span>
            SCAN TYPE
          </span>

          <b>
            {data.scan_type}
          </b>

        </div>


        <div>

          <span>
            DATE
          </span>

          <b>
            {new Date(
              data.completed_at
            ).toLocaleString()}
          </b>

        </div>

      </div>


      {/* ===================================================
          CHART + PORTS
      =================================================== */}

      <div className="result-grid">


        <div className="panel">

          <div className="panel-head">
            SEVERITY DISTRIBUTION
          </div>


          <div className="chart">

            <ResponsiveContainer
              width="100%"
              height={250}
            >

              <PieChart>

                <Pie
                  data={counts}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={65}
                  outerRadius={95}
                >

                  {counts.map(
                    (entry, index) => (
                      <Cell
                        key={entry.name}
                        fill={
                          chartColors[
                          index %
                          chartColors.length
                          ]
                        }
                      />
                    )
                  )}

                </Pie>

                <Tooltip />

              </PieChart>

            </ResponsiveContainer>

          </div>

        </div>


        <div className="panel">

          <div className="panel-head">
            OPEN PORTS
          </div>


          {data.ports
            .filter(
              (port) =>
                port.state === "OPEN"
            )
            .map((port) => (

              <div
                className="port"
                key={port.port}
              >

                <b>
                  {port.port}
                </b>

                <span>
                  {port.service}
                </span>

                <em>
                  {port.risk}
                </em>

              </div>

            ))}


          {!data.ports.some(
            (port) =>
              port.state === "OPEN"
          ) && <Empty />}

        </div>

      </div>


      {/* ===================================================
          FINDINGS
      =================================================== */}

      <div className="panel">

        <div className="panel-head">

          FINDINGS

          <span>
            {data.findings.length}
          </span>

        </div>


        {data.findings.map(
          (finding, index) => (

            <details
              className="finding"
              key={index}
            >

              <summary>

                <strong
                  className={`sev ${finding.severity}`}
                >
                  {finding.severity}
                </strong>

                <b>
                  {finding.title}
                </b>

                <span>
                  {finding.category}
                </span>

              </summary>


              <div>

                <p>
                  <b>Description:</b>{" "}
                  {finding.description}
                </p>

                <p>
                  <b>Evidence:</b>{" "}
                  {finding.evidence}
                </p>

                <p>
                  <b>Impact:</b>{" "}
                  {finding.impact}
                </p>

                <p>
                  <b>Recommendation:</b>{" "}
                  {finding.recommendation}
                </p>


                {finding.reference && (
                  <p>
                    <b>Reference:</b>{" "}
                    {finding.reference}
                  </p>
                )}

              </div>

            </details>

          )
        )}


        {!data.findings.length && (
          <Empty />
        )}

      </div>

      <ThreatIntelligence
        intelligence={data.intelligence || []}
      />

    </Shell>
  );
}

/* =========================================================
   THREAT INTELLIGENCE
========================================================= */

function ThreatIntelligence({ intelligence = [] }) {
  return (
    <div className="panel threat-intel">
      <div className="panel-head">
        <span>
          <Globe size={17} />
          {" "}THREAT INTELLIGENCE
        </span>

        <span>
          {intelligence.length} RESULTS
        </span>
      </div>

      <p className="intel-description">
        Public security research retrieved through
        SerpApi to provide additional context for
        your scan findings.
      </p>

      {!intelligence.length ? (
        <div className="empty">
          No intelligence results are available for
          this scan. This does not mean the target is
          secure or vulnerable.
        </div>
      ) : (
        <div className="intel-list">
          {intelligence.map((item, index) => (
            <article
              className="intel-card"
              key={`${item.link || item.query}-${index}`}
            >
              <div className="intel-meta">
                <span className="intel-source">
                  <Globe size={13} />
                  {item.source || "Public web source"}
                </span>

                {item.date && (
                  <span className="intel-date">
                    {item.date}
                  </span>
                )}
              </div>

              <h3>
                {item.title || "Untitled security result"}
              </h3>

              <p className="intel-snippet">
                {item.snippet ||
                  "No description was provided by the search result."}
              </p>

              <div className="intel-query">
                <span>SEARCH QUERY</span>
                <p>{item.query || "Security research"}</p>
              </div>

              {item.link && (
                <a
                  className="intel-link"
                  href={item.link}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  VIEW SOURCE
                  <ExternalLink size={14} />
                </a>
              )}
            </article>
          ))}
        </div>
      )}
    </div>
  );
}


/* =========================================================
   HISTORY
========================================================= */

function HistoryPage() {

  const [scans, setScans] =
    useState([]);


  useEffect(() => {

    axios
      .get(`${API}/api/scans`, {
        headers: authHeaders(),
      })
      .then((response) => {
        setScans(response.data);
      })
      .catch((error) => {
        console.error(error);
      });

  }, []);


  return (
    <Shell>

      <PageTitle
        title="SCAN HISTORY"
        sub="Previous security assessments."
      />


      <div className="panel table-wrap">

        <table>

          <thead>

            <tr>
              <th>Target</th>
              <th>Date</th>
              <th>Type</th>
              <th>Score</th>
              <th>Status</th>
              <th />
            </tr>

          </thead>


          <tbody>

            {scans.map((scan) => (

              <tr key={scan.id}>

                <td>
                  {scan.target}
                </td>

                <td>
                  {new Date(
                    scan.completed_at
                  ).toLocaleString()}
                </td>

                <td>
                  {scan.scan_type}
                </td>

                <td>
                  <b>
                    {scan.security_score}
                  </b>
                </td>

                <td>
                  {scan.status}
                </td>

                <td>

                  <Link
                    to={`/scan/${scan.id}`}
                  >
                    VIEW
                  </Link>

                </td>

              </tr>

            ))}

          </tbody>

        </table>


        {!scans.length && (
          <Empty />
        )}

      </div>

    </Shell>
  );
}


/* =========================================================
   REPORTS
========================================================= */

function Reports() {

  return (
    <Shell>

      <PageTitle
        title="REPORTS"
        sub="Security assessment reports."
      />


      <div className="panel">

        <p>
          Open a completed scan from your
          scan history to download the
          professional VULN-X PDF report.
        </p>


        <Link
          className="red-btn"
          to="/history"
        >
          OPEN SCAN HISTORY
        </Link>

      </div>

    </Shell>
  );
}


/* =========================================================
   GENERIC PAGE
========================================================= */

function Generic({
  title,
  sub,
  children,
}) {

  return (
    <Shell>

      <PageTitle
        title={title}
        sub={sub}
      />

      <div className="panel prose">
        {children}
      </div>

    </Shell>
  );
}


/* =========================================================
   PROFILE
========================================================= */

function Profile() {

  const { user } = useAuth();

  return (
    <Shell>

      <PageTitle
        title="PROFILE"
        sub="Operator account."
      />


      <div className="panel profile">

        <div className="avatar">
          {user?.name?.[0] || "V"}
        </div>

        <h2>
          {user?.name}
        </h2>

        <p>
          @{user?.username}
        </p>

        <p>
          {user?.email}
        </p>

      </div>

    </Shell>
  );
}


/* =========================================================
   APP
========================================================= */

function App() {

  return (

    <Provider>

      <Routes>

        <Route
          path="/"
          element={<Landing />}
        />

        <Route
          path="/login"
          element={<AuthPage />}
        />

        <Route
          path="/register"
          element={
            <AuthPage register />
          }
        />


        <Route
          path="/dashboard"
          element={
            <Protected>
              <Dashboard />
            </Protected>
          }
        />


        <Route
          path="/scanner"
          element={
            <Protected>
              <Scanner />
            </Protected>
          }
        />


        <Route
          path="/scan/:id"
          element={
            <Protected>
              <ScanRoute />
            </Protected>
          }
        />


        <Route
          path="/history"
          element={
            <Protected>
              <HistoryPage />
            </Protected>
          }
        />


        <Route
          path="/reports"
          element={
            <Protected>
              <Reports />
            </Protected>
          }
        />


        <Route
          path="/security-center"
          element={
            <Protected>

              <Generic
                title="SECURITY CENTER"
                sub="Operational security guidance."
              >

                <p>
                  Review your findings,
                  prioritize high-severity issues,
                  minimize unnecessary exposed
                  services, and keep observable
                  software current.
                </p>

                <p>
                  VULN-X intentionally performs
                  non-destructive assessment only.
                </p>

              </Generic>

            </Protected>
          }
        />


        <Route
          path="/profile"
          element={
            <Protected>
              <Profile />
            </Protected>
          }
        />


        <Route
          path="/settings"
          element={
            <Protected>

              <Generic
                title="SETTINGS"
                sub="Account and scanner preferences."
              >

                <p>
                  Authentication uses JWT sessions.
                  Keep your backend JWT secret private
                  and change it before production deployment.
                </p>

              </Generic>

            </Protected>
          }
        />


        <Route
          path="*"
          element={
            <Navigate
              to="/"
              replace
            />
          }
        />

      </Routes>

    </Provider>
  );
}


/* =========================================================
   SCAN ROUTE
========================================================= */

function ScanRoute() {

  const { id } = useParams();

  return (
    <Scan id={id} />
  );
}


/* =========================================================
   START APPLICATION
========================================================= */

const root =
  document.getElementById("root");

root &&
  React.createElement;

import("react-dom/client").then(
  ({ createRoot }) => {

    createRoot(root).render(
      <BrowserRouter>
        <App />
      </BrowserRouter>
    );

  }
);