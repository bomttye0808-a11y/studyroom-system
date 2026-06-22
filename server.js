const express = require('express');
require('dotenv').config();
const path = require('path');
const cors = require('cors');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'salesioadmin15130!';
const JWT_SECRET = process.env.JWT_SECRET || 'salesio_secret_key_2026_!@';

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// 600명 동시 접속 통제를 위한 대규모 커넥션 풀 구축
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || 'your_password',
    database: process.env.DB_NAME || 'salesio_studyroom',
    port: Number(process.env.DB_PORT) || 3306,
    waitForConnections: true,
    connectionLimit: 60,
    queueLimit: 0
});

// 영속성 보장 스키마 테이블 자동 초기화 및 구조적 인덱스 정의
async function initDatabase() {
    const conn = await pool.getConnection();
    try {
        // 오늘의 야자 감독 선생님 이름을 무중단 안전하게 영속화하기 위한 설정 메타 테이블 신설
        await conn.query(`
            CREATE TABLE IF NOT EXISTS system_config (
                cfg_key VARCHAR(50) PRIMARY KEY,
                cfg_value TEXT NULL
            )
        `);

        // 초기 데이터가 없을 경우 가이드라인에 맞춰 빈 문자열('') 상태로 레코드 생성
        await conn.query(`
            INSERT IGNORE INTO system_config (cfg_key, cfg_value) VALUES ('supervisor_name', '')
        `);

        await conn.query(`
            CREATE TABLE IF NOT EXISTS student_master (
                student_id VARCHAR(10) PRIMARY KEY,
                name VARCHAR(50) NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        `);
        await conn.query(`
            CREATE TABLE IF NOT EXISTS passwords (
                student_id VARCHAR(10) PRIMARY KEY,
                password_hash VARCHAR(255) NOT NULL,
                FOREIGN KEY (student_id) REFERENCES student_master(student_id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        `);
        await conn.query(`
            CREATE TABLE IF NOT EXISTS reservations (
                id INT AUTO_INCREMENT PRIMARY KEY,
                day VARCHAR(20) NOT NULL,
                room_type VARCHAR(20) NOT NULL,
                seat_id VARCHAR(20) NOT NULL,
                student_id VARCHAR(10) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY unique_seat (day, seat_id),
                UNIQUE KEY unique_student (day, student_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        `);
        await conn.query(`
            CREATE TABLE IF NOT EXISTS comments (
                id INT AUTO_INCREMENT PRIMARY KEY,
                parent_id INT DEFAULT NULL,
                student_id VARCHAR(10) NOT NULL,
                anon_name VARCHAR(50) NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        `);
        await conn.query(`
            CREATE TABLE IF NOT EXISTS reports (
                id INT AUTO_INCREMENT PRIMARY KEY,
                comment_id INT NOT NULL,
                reporter_id VARCHAR(10) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY unique_report (comment_id, reporter_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        `);
        await conn.query(`
            CREATE TABLE IF NOT EXISTS attendance_noshow (
                id INT AUTO_INCREMENT PRIMARY KEY,
                student_id VARCHAR(10) NOT NULL,
                type ENUM('RESERVED', 'ATTEND', 'EARLY_LEAVE', 'ABSENT', 'NOSHOW_WARN') NOT NULL,
                date DATE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY unique_student_date (student_id, date)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        `);

        await conn.query(`
            CREATE TABLE IF NOT EXISTS noshow_warnings (
                id INT AUTO_INCREMENT PRIMARY KEY,
                student_id VARCHAR(10) NOT NULL,
                student_name VARCHAR(50) NOT NULL,
                grade_class VARCHAR(10) NOT NULL,
                warning_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reason TEXT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        `);
        await conn.query(`
            CREATE TABLE IF NOT EXISTS queue (
                id INT AUTO_INCREMENT PRIMARY KEY,
                day VARCHAR(20) NOT NULL,
                seat_id VARCHAR(20) NOT NULL,
                student_id VARCHAR(10) NOT NULL,
                priority INT NOT NULL,
                notified INT DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY unique_queue (day, seat_id, student_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        `);
        await conn.query(`
            CREATE TABLE IF NOT EXISTS system_config (
                cfg_key VARCHAR(50) PRIMARY KEY,
                cfg_value TEXT
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        `);
        await conn.query(`
            CREATE TABLE IF NOT EXISTS comment_likes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                comment_id INT NOT NULL,
                student_id VARCHAR(10) NOT NULL,
                UNIQUE KEY unique_like (comment_id, student_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        `);
        await conn.query(`
            CREATE TABLE IF NOT EXISTS whispers (
                id INT AUTO_INCREMENT PRIMARY KEY,
                student_id VARCHAR(10) NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        `);
        console.log("✔ [System] MySQL 아키텍처 테이블 생성 완료 및 풀 바인딩 성공.");
    } catch (err) {
        console.error("❌ 데이터베이스 초기화 실패:", err);
    } finally {
        conn.release();
    }
}
initDatabase();

// ==========================================
// Step 5. 백엔드 중심의 관리자 권한 교차 검증 게이트 미들웨어
// ==========================================
function adminAuthorizationGate(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: '인가되지 않은 접근 권한입니다. (토큰 유실)' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: '보안 검증 토큰이 유효하지 않습니다.' });
        
        // F12 변조 방지 교차 매칭 검증 강화: 토큰 내 studentId가 철자까지 완벽히 'salesio'인지 검증
        if (user.studentId !== 'salesio') {
            return res.status(403).json({ message: '위조된 접근 시도입니다. 해당 행위는 로그에 기록됩니다.' });
        }
        req.adminUser = user;
        next();
    });
}

// [관리자 전용 API 전역 필터링 레이어 적용]
// 기존 바디 패스워드 검증 방식과 상호 보완 교차 배치하여 완벽 보호막 형성
app.use('/api/admin/', (req, res, next) => {
    if (req.body && req.body.password === ADMIN_PASSWORD) {
        return next();
    }
    adminAuthorizationGate(req, res, next);
});

// [유틸리티] 비속어 마스킹 처리 엔진
async function applyCensorship(text) {
    if (!text) return text;
    try {
        const [rows] = await pool.query("SELECT cfg_value FROM system_config WHERE cfg_key = 'censored_words'");
        if (rows.length === 0 || !rows[0].cfg_value) return text;
        
        const words = JSON.parse(rows[0].cfg_value);
        let censored = text;
        words.forEach(word => {
            if (!word.trim()) return;
            const regex = new RegExp(word.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&'), 'gi');
            censored = censored.replace(regex, '*'.repeat(word.length));
        });
        return censored;
    } catch (err) {
        return text;
    }
}

// [유틸리티] 유저별 고정 익명 번호 추적 인덱싱 엔진
async function getAnonymousId(studentId) {
    const [rows] = await pool.query("SELECT anon_name FROM comments WHERE student_id = ? LIMIT 1", [studentId]);
    if (rows.length > 0) return rows[0].anon_name;

    const [maxRows] = await pool.query("SELECT anon_name FROM comments WHERE anon_name LIKE '익명%'");
    let maxAnonNum = 0;
    maxRows.forEach(r => {
        const num = parseInt(r.anon_name.replace('익명', ''), 10);
        if (!isNaN(num) && num > maxAnonNum) maxAnonNum = num;
    });
    return `익명${maxAnonNum + 1}`;
}

// ================= [ 유저 전용 핵심 API 엔드포인트 ] =================

// [API] 실시간 폴링 상태 일괄 결합 통합 뷰 데이터셋 반환
app.get('/api/status', async (req, res) => {
    try {
        const [resRows] = await pool.query("SELECT day, seat_id, room_type, student_id FROM reservations");
        const [cfgRows] = await pool.query("SELECT cfg_value FROM system_config WHERE cfg_key = 'open_time'");
        const [cntRows] = await pool.query("SELECT COUNT(*) as cnt FROM comments");

        const reservations = {};
        resRows.forEach(row => {
            if (!reservations[row.day]) reservations[row.day] = {};
            reservations[row.day][row.seat_id] = { studentId: row.student_id, roomType: row.room_type };
        });

        const todayStr = new Date().toISOString().split('T')[0];
        const [attendanceRows] = await pool.query("SELECT student_id, type FROM attendance_noshow WHERE date = ?", [todayStr]);
        
        const attendanceMap = {};
        attendanceRows.forEach(att => {
            attendanceMap[att.student_id] = att.type;
        });

        const openTime = cfgRows.length > 0 ? cfgRows[0].cfg_value : "";
        res.json({ reservations, openTime, commentsCount: cntRows[0].cnt, attendanceMap });
    } catch (err) {
        res.status(500).json({ message: '상태 조회 중 오류 발생' });
    }
});

// [API] 학적부 기반 패스워드 최초 가입 및 통합 인증 모듈
app.post('/api/login', async (req, res) => {
    const { studentId, password } = req.body;

    if (studentId === 'salesio' && password === ADMIN_PASSWORD) {
        const token = jwt.sign({ studentId: 'salesio', role: 'admin' }, JWT_SECRET, { expiresIn: '8h' });
        return res.json({ success: true, isAdmin: true, name: '관리자', token: token });
    }

    try {
        const [master] = await pool.query("SELECT name FROM student_master WHERE student_id = ?", [studentId]);
        if (master.length === 0) {
            return res.status(400).json({ success: false, message: '등록되지 않은 학번입니다.' });
        }

        const [pwRows] = await pool.query("SELECT password_hash FROM passwords WHERE student_id = ?", [studentId]);
        
        if (pwRows.length === 0) {
            if (password && password.length === 4 && !isNaN(password)) {
                await pool.query("INSERT INTO passwords (student_id, password_hash) VALUES (?, ?)", [studentId, password]);
                const token = jwt.sign({ studentId: studentId, role: 'student' }, JWT_SECRET, { expiresIn: '8h' });
                return res.json({ success: true, isAdmin: false, name: master[0].name, token: token });
            } else {
                return res.status(400).json({ success: false, message: '최초 비밀번호는 숫자 4자리여야 합니다.' });
            }
        } else {
            if (pwRows[0].password_hash !== password) {
                return res.status(400).json({ success: false, message: '학번/비밀번호가 일치하지 않습니다.' });
            }
            const token = jwt.sign({ studentId: studentId, role: 'student' }, JWT_SECRET, { expiresIn: '8h' });
            return res.json({ success: true, isAdmin: false, name: master[0].name, token: token });
        }
    } catch (err) {
        console.error("로그인 오류 상세:", err);
        res.status(500).json({ message: '로그인 검증 시스템 에러' });
    }
});

// [API] 입력 학번 실시간 명단 존재 검증 리스너
app.get('/api/student-check/:id', async (req, res) => {
    const studentId = req.params.id;
    try {
        const [master] = await pool.query("SELECT name FROM student_master WHERE student_id = ?", [studentId]);
        if (master.length > 0) {
            const [pwRows] = await pool.query("SELECT student_id FROM passwords WHERE student_id = ?", [studentId]);
            res.json({ exists: true, name: master[0].name, isRegistered: pwRows.length > 0 });
        } else {
            res.json({ exists: false });
        }
    } catch (err) {
        res.status(500).json({ message: '학생 검증 오류' });
    }
});

// [API] 고밀도 동시성 제어 적용 단일 예약 및 요일별 변경 트랜잭션 라우터
app.post('/api/reserve', async (req, res) => {
    const { studentId, day, roomType, seatId } = req.body;
    const conn = await pool.getConnection();

    try {
        await conn.beginTransaction();

        const [cfgRows] = await conn.query("SELECT cfg_value FROM system_config WHERE cfg_key = 'open_time'");
        const openTime = cfgRows.length > 0 ? cfgRows[0].cfg_value : "";
        if (!openTime || new Date(openTime) > new Date()) {
            await conn.rollback();
            return res.status(403).json({ message: '아직 예약 시간이 아닙니다.' });
        }

        const [existing] = await conn.query("SELECT seat_id FROM reservations WHERE day = ? AND student_id = ?", [day, studentId]);
        let canceledSeat = null;
        if (existing.length > 0) {
            canceledSeat = existing[0].seat_id;
            await conn.query("DELETE FROM reservations WHERE day = ? AND student_id = ?", [day, studentId]);
        }

        const [seatCheck] = await conn.query("SELECT id FROM reservations WHERE day = ? AND seat_id = ? FOR UPDATE", [day, seatId]);
        if (seatCheck.length > 0) {
            await conn.rollback();
            return res.status(400).json({ message: '이미 선점된 좌석입니다.' });
        }

        await conn.query("INSERT INTO reservations (day, room_type, seat_id, student_id) VALUES (?, ?, ?, ?)", [day, roomType, seatId, studentId]);

        await conn.commit();
        res.json({ success: true, canceledSeat, newSeat: seatId });
    } catch (err) {
        await conn.rollback();
        res.status(500).json({ message: '실시간 좌석 예약 트랜잭션 에러' });
    } finally {
        conn.release();
    }
});

// ==========================================
// Step 7. 대기열(예약 알림 신청) 취소 및 순차 대기열 트랜잭션 자동 배정 양도 로직
// ==========================================
app.post('/api/cancel', async (req, res) => {
    const { studentId, day, seatId } = req.body;
    const conn = await pool.getConnection();

    try {
        await conn.beginTransaction();

        const [target] = await conn.query("SELECT id FROM reservations WHERE day = ? AND seat_id = ? AND student_id = ?", [day, seatId, studentId]);
        if (target.length === 0) {
            await conn.rollback();
            return res.status(400).json({ message: '유효한 예약 내역이 검색되지 않습니다.' });
        }

        // 1. 기존 취소 신청 좌석 파기
        await conn.query("DELETE FROM reservations WHERE day = ? AND seat_id = ?", [day, seatId]);

        // 2. 대기열 최우선 순위 1명 탐색 추출 (트랜잭션 락 처리)
        const [nextQueue] = await conn.query(
            "SELECT student_id, id FROM queue WHERE day = ? AND seat_id = ? AND notified = 0 ORDER BY priority ASC, created_at ASC LIMIT 1 FOR UPDATE",
            [day, seatId]
        );

        let transferredStudent = null;
        if (nextQueue.length > 0) {
            transferredStudent = nextQueue[0].student_id;
            const queueTableId = nextQueue[0].id;
            const targetRoomType = seatId.toUpperCase().startsWith('M') ? 'MARIA' : 'AI';

            // 3. 공백이 생긴 즉시 대기 1순위 학생에게 좌석 자동 배정 양도
            await conn.query(
                "INSERT INTO reservations (day, room_type, seat_id, student_id) VALUES (?, ?, ?, ?)",
                [day, targetRoomType, seatId, transferredStudent]
            );

            // 4. 알림 수신 대상 예약 완료 트리거 인덱스 전송 설정 (notified = 1)
            await conn.query("UPDATE queue SET notified = 1 WHERE id = ?", [queueTableId]);
        }

        await conn.commit();
        res.json({ success: true, automaticallyTransferred: !!transferredStudent, target: transferredStudent });
    } catch (err) {
        await conn.rollback();
        res.status(500).json({ message: '예약 취소 및 자동 양도 트랜잭션 처리 실패' });
    } finally {
        conn.release();
    }
});

// [API] 로그인/리프레시 대기열 자동 양도 완료 알림 안내 팝업 서브 라우터
app.get('/api/queue-notification/:studentId', async (req, res) => {
    const { studentId } = req.params;
    try {
        const [notifications] = await pool.query("SELECT seat_id, day FROM queue WHERE student_id = ? AND notified = 1", [studentId]);
        if (notifications.length > 0) {
            // 사용자 확인 후 코드 스케줄 파기 처리 완료 전이 (notified = 2)
            await pool.query("UPDATE queue SET notified = 2 WHERE student_id = ? AND notified = 1", [studentId]);
        }
        res.json({ newAllocations: notifications });
    } catch (err) {
        res.status(500).json({ message: '알림 상태 확인 실패' });
    }
});

// [API] 커뮤니티 전 게시글 및 개별 댓글 마스킹 정제 반환
app.get('/api/comments', async (req, res) => {
    try {
        const [cfgRows] = await pool.query("SELECT cfg_value FROM system_config WHERE cfg_key = 'sys_notice'");
        const [commentRows] = await pool.query(`
            SELECT c.id, c.parent_id as parentId, c.student_id as writer, c.anon_name as anonName, 
                   c.content as text, DATE_FORMAT(c.created_at, '%m/%d %H:%i') as date,
                   (SELECT COUNT(*) FROM comment_likes WHERE comment_id = c.id) as likeCount
            FROM comments c ORDER BY c.id ASC
        `);

        const formattedComments = await Promise.all(commentRows.map(async (c) => {
            const [likesRows] = await pool.query("SELECT student_id FROM comment_likes WHERE comment_id = ?", [c.id]);
            return {
                ...c,
                likes: likesRows.map(l => l.student_id)
            };
        }));

        const notice = cfgRows.length > 0 ? cfgRows[0].cfg_value : "";
        res.json({ notice, comments: formattedComments });
    } catch (err) {
        res.status(500).json({ message: '게시판 조회 에러' });
    }
});

// [API] 익명 소통 게시판 실시간 댓글 등록 엔진
app.post('/api/comments/add', async (req, res) => {
    const { studentId, text, parentId } = req.body;

    try {
        const [master] = await pool.query("SELECT name FROM student_master WHERE student_id = ?", [studentId]);
        if (master.length === 0) return res.status(403).json({ message: '권한이 없습니다.' });

        const [banRows] = await pool.query(
            "SELECT created_at FROM attendance_noshow WHERE student_id = ? AND type = 'NOSHOW_WARN' ORDER BY id DESC LIMIT 1",
            [studentId]
        );
        if (banRows.length > 0) {
            const bannedTime = new Date(banRows[0].created_at).getTime();
            const oneWeekMs = 7 * 24 * 60 * 60 * 1000;
            if (new Date().getTime() - bannedTime < oneWeekMs) {
                return res.status(403).json({ message: '🚨 누적 신고 혹은 블랙리스트 정책에 기해 글쓰기가 7일간 전면 제한되었습니다.' });
            }
        }

        const filteredText = await applyCensorship(text);
        const anonName = await getAnonymousId(studentId);

        const [result] = await pool.query(
            "INSERT INTO comments (parent_id, student_id, anon_name, content) VALUES (?, ?, ?, ?)",
            [parentId || null, studentId, anonName, filteredText]
        );

        const now = new Date();
        const dateStr = `${String(now.getMonth() + 1).padStart(2, '0')}/${String(now.getDate()).padStart(2, '0')} ${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;

        res.json({
            success: true,
            comment: {
                id: result.insertId,
                parentId: parentId || null,
                writer: studentId,
                anonName: anonName,
                text: filteredText,
                date: dateStr,
                likes: []
            }
        });
    } catch (err) {
        res.status(500).json({ message: '댓글 작성 오류' });
    }
});

// ==========================================
// Step 6. 중복 신고 테러 방지 로직 (DB 수준 UNIQUE 제약 조건 결합)
// ==========================================
app.post('/api/comments/report', async (req, res) => {
    const { commentId, reporterId } = req.body;
    if (!commentId || !reporterId) return res.status(400).json({ message: '인자가 누락되었습니다.' });

    const conn = await pool.getConnection();
    try {
        await conn.beginTransaction();

        // 1. 중복 신고 차단 교차 이력 확인 검증
        const [existingReport] = await conn.query("SELECT id FROM reports WHERE comment_id = ? AND reporter_id = ?", [commentId, reporterId]);
        if (existingReport.length > 0) {
            await conn.rollback();
            return res.status(400).json({ message: '🚨 이미 신고를 접수한 익명 글/댓글입니다. 한 학생은 한 글당 딱 1번만 신고할 수 있습니다.' });
        }

        // 2. 신규 무결성 신고 데이터 이력 매핑 기록
        await conn.query("INSERT INTO reports (comment_id, reporter_id) VALUES (?, ?)", [commentId, reporterId]);

        // 3. 누적 카운트 조회 연산 후 3회 이상 검출 시 제재 처리 자동 통제
        const [countRows] = await conn.query("SELECT COUNT(*) as total_reports FROM reports WHERE comment_id = ?", [commentId]);
        const currentReportCount = countRows[0].total_reports;

        const [commentRows] = await conn.query("SELECT student_id FROM comments WHERE id = ?", [commentId]);
        if (commentRows.length > 0) {
            const writerStudentId = commentRows[0].student_id;
            if (currentReportCount >= 3 && writerStudentId && writerStudentId !== 'salesio') {
                const todayStr = new Date().toISOString().split('T')[0];
                await conn.query("INSERT INTO attendance_noshow (student_id, type, date) VALUES (?, 'NOSHOW_WARN', ?)", [writerStudentId, todayStr]);
            }
        }

        await conn.commit();
        res.json({ success: true, message: '정상적으로 신고 처리가 완료되었습니다.', currentReports: currentReportCount });
    } catch (err) {
        await conn.rollback();
        // UNIQUE KEY 익셉션 에러 레이어 한 번 더 바인딩 처리
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ message: '🚨 이미 신고를 접수한 익명 글/댓글입니다. 중복 신고는 불가능합니다.' });
        }
        res.status(500).json({ message: '신고 처리 중 오류 발생' });
    } finally {
        conn.release();
    }
});

// [API] 익명 댓글 편집 및 실시간 마스킹 커밋
app.post('/api/comments/edit', async (req, res) => {
    const { commentId, studentId, text } = req.body;
    try {
        const [rows] = await pool.query("SELECT student_id FROM comments WHERE id = ?", [commentId]);
        if (rows.length === 0 || rows[0].student_id !== studentId) {
            return res.status(403).json({ message: '수정 권한이 없습니다.' });
        }
        const filteredText = await applyCensorship(text);
        await pool.query("UPDATE comments SET content = ? WHERE id = ?", [filteredText, commentId]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: '댓글 수정 실패' });
    }
});

// [API] 익명 댓글 파기 삭제 처리
app.post('/api/comments/delete', async (req, res) => {
    const { commentId, studentId } = req.body;
    try {
        const [rows] = await pool.query("SELECT student_id FROM comments WHERE id = ?", [commentId]);
        if (rows.length === 0 || rows[0].student_id !== studentId) {
            return res.status(403).json({ message: '삭제 권한이 없습니다.' });
        }
        await pool.query("DELETE FROM comments WHERE id = ?", [commentId]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: '댓글 삭제 실패' });
    }
});

// [API] 무결성이 보장된 좋아요 상태 분기 토글
app.post('/api/comments/like', async (req, res) => {
    const { commentId, studentId } = req.body;
    try {
        const [rows] = await pool.query("SELECT id FROM comments WHERE id = ?", [commentId]);
        if (rows.length === 0) return res.status(444).json({ message: '댓글이 존재하지 않습니다.' });

        const [likeCheck] = await pool.query("SELECT id FROM comment_likes WHERE comment_id = ? AND student_id = ?", [commentId, studentId]);
        if (likeCheck.length === 0) {
            await pool.query("INSERT INTO comment_likes (comment_id, student_id) VALUES (?, ?)", [commentId, studentId]);
        } else {
            await pool.query("DELETE FROM comment_likes WHERE comment_id = ? AND student_id = ?", [commentId, studentId]);
        }

        const [countRows] = await pool.query("SELECT COUNT(*) as cnt FROM comment_likes WHERE comment_id = ?", [commentId]);
        res.json({ success: true, likesCount: countRows[0].cnt });
    } catch (err) {
        res.status(500).json({ message: '좋아요 토글 실패' });
    }
});

// [API] 1:1 관리자 귓속말 발신 라우터
app.post('/api/whisper/send', async (req, res) => {
    const { studentId, text } = req.body;
    try {
        const [master] = await pool.query("SELECT name FROM student_master WHERE student_id = ?", [studentId]);
        if (master.length === 0) return res.status(403).json({ message: '인증 실패' });

        await pool.query("INSERT INTO whispers (student_id, content) VALUES (?, ?)", [studentId, text]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: '귓속말 발신 실패' });
    }
});

// [API] 자기 자신의 귓속말 수신 대화함 이력 탐색 조회
app.get('/api/whisper/my/:id', async (req, res) => {
    try {
        const [rows] = await pool.query(`
            SELECT w.student_id as studentId, sm.name, w.content as text, 
                   DATE_FORMAT(w.created_at, '%Y-%m-%d %H:%i') as time
            FROM whispers w
            JOIN student_master sm ON w.student_id = sm.student_id
            WHERE w.student_id = ? ORDER BY w.id ASC
        `, [req.params.id]);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ message: '내 귓속말 조회 실패' });
    }
});

// ================= [ 최고 관리자(ADMIN) 전용 API 엔드포인트 ] =================

// ==========================================
// Step 3. 관리자 전용 좌석 제어 및 비공개 출결/노쇼 누적 저장 모듈
// ==========================================
app.post('/api/admin/attendance-action', async (req, res) => {
    const { studentId, actionType } = req.body; // actionType: 'EARLY_LEAVE', 'ABSENT', 'NOSHOW_WARN'
    try {
        const todayStr = new Date().toISOString().split('T')[0];
        // 일자별 며칠이든 몇 달이든 안전하게 누적 테이블 적재 처리
        await pool.query("INSERT INTO attendance_noshow (student_id, type, date) VALUES (?, ?, ?)", [studentId, actionType, todayStr]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: '출결/노쇼 액션 처리 실패' });
    }
});

// 관리자용 비공개 노쇼/출결 정보 반별 추적 및 통계 조회 API (보안 엄수)
app.post('/api/admin/noshow-history', async (req, res) => {
    const { grade, classNum } = req.body;
    try {
        // Step 4 반별 로직 연동: 학번 앞 자리를 분석 기점으로 조회용 와일드카드 구현
        const pattern = `${grade}${String(classNum).padStart(2, '0')}%`;
        const [rows] = await pool.query(`
            SELECT a.student_id, sm.name, COUNT(a.id) as warn_count, GROUP_CONCAT(DATE_FORMAT(a.date, '%Y-%m-%d')) as dates
            FROM attendance_noshow a
            JOIN student_master sm ON a.student_id = sm.student_id
            WHERE a.type = 'NOSHOW_WARN' AND a.student_id LIKE ?
            GROUP BY a.student_id, sm.name
        `, [pattern]);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ message: '경고 이력 조회 실패' });
    }
});

// [ADMIN API] 공지사항 원격 데이터 변경 커밋
app.post('/api/admin/notice', async (req, res) => {
    const { text } = req.body;
    try {
        await pool.query("INSERT INTO system_config (cfg_key, cfg_value) VALUES ('sys_notice', ?) ON DUPLICATE KEY UPDATE cfg_value = ?", [text, text]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: '공지사항 수정 실패' });
    }
});

// ==========================================
// Step 2. 학적부 데이터 영구 보존 및 완전 대체 (TRUNCATE 초기화 통제)
// ==========================================
// 기존 sync-students와 upload-students의 주소 처리 혼선 방지를 위한 통일 바인딩
const handleExcelSync = async (req, res) => {
    const { students } = req.body; // [{studentId, name}]
    const conn = await pool.getConnection();
    try {
        await conn.beginTransaction();

        // [제약 조건] 자습실 예약 현황이 완전히 비어있을 때만 대체 승인 검증
        const [resRows] = await conn.query("SELECT COUNT(*) as cnt FROM reservations");
        if (resRows[0].cnt > 0) {
            await conn.rollback();
            return res.status(400).json({ message: '예약 현황이 완전히 초기화(비어있는 상태)된 상태에서만 학적부 엑셀 업로드가 허용됩니다.' });
        }

        // 기존 테이블 완전 초기화 대체 이행 (TRUNCATE 처리)
        await conn.query("SET FOREIGN_KEY_CHECKS = 0;");
        await conn.query("TRUNCATE TABLE passwords;");
        await conn.query("TRUNCATE TABLE student_master;");
        await conn.query("SET FOREIGN_KEY_CHECKS = 1;");

        // 엑셀 파싱 전송 구조가 유실 없이 안정 적재되도록 키 매핑 수렴 보안 조치
        if (students && students.length > 0) {
            const insertQuery = "INSERT INTO student_master (student_id, name) VALUES ?";
            const values = students.map(s => {
                const sId = s.studentId || s.student_id || s['학번'];
                const sName = s.name || s['이름'];
                return [sId, sName];
            });
            await conn.query(insertQuery, [values]);
        }

        await conn.commit();
        res.json({ success: true, count: students.length, message: "학적부 데이터가 성공적으로 완전 대체 및 영구 보존되었습니다." });
    } catch (err) {
        await conn.rollback();
        console.error(err);
        res.status(500).json({ message: '학적 마스터 데이터 동기화 에러' });
    } finally {
        conn.release();
    }
};

// 프론트엔드가 요청할 수 있는 두 개 엔드포인트 모두 완벽 매핑 대응 조치
app.post('/api/admin/sync-students', handleExcelSync);
app.post('/api/admin/upload-students', handleExcelSync);

// ==========================================
// Step 4. 학번 분석 기반 반별 명단 정리 데이터 가공
// ==========================================
app.post('/api/admin/report-by-class', async (req, res) => {
    try {
        const [reservations] = await pool.query(`
            SELECT r.seat_id, r.room_type, r.day, sm.student_id, sm.name
            FROM reservations r
            JOIN student_master sm ON r.student_id = sm.student_id
        `);

        const structuredData = {};
        reservations.forEach(r => {
            const sid = String(r.student_id);
            // 학번 5자리 규칙성 마스킹 해독 검증
            if (sid.length === 5) {
                const grade = sid.substring(0, 1);            // 1번째 자리: 학년
                const classNum = parseInt(sid.substring(1, 3), 10); // 2~3번째 자리: 반
                const number = sid.substring(3, 5);            // 4~5번째 자리: 번호

                if (!structuredData[grade]) structuredData[grade] = {};
                if (!structuredData[grade][classNum]) structuredData[grade][classNum] = [];

                structuredData[grade][classNum].push({
                    studentId: sid,
                    name: r.name,
                    seatId: r.seat_id,
                    roomType: r.room_type,
                    day: r.day,
                    number: number
                });
            }
        });
        res.json(structuredData);
    } catch (err) {
        res.status(500).json({ message: '반별 통계 데이터 가공 에러' });
    }
});

// [ADMIN API] 인라인 리스트 마스터 전원 출력 조회
app.post('/api/admin/students-list', async (req, res) => {
    try {
        const [rows] = await pool.query(`
            SELECT sm.student_id as studentId, sm.name, p.password_hash as password
            FROM student_master sm
            LEFT JOIN passwords p ON sm.student_id = p.student_id
        `);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ message: '인라인 리스트 조회 실패' });
    }
});

// [ADMIN API] 특정 유저 강제 비밀번호 재할당 변경
app.post('/api/admin/change-student-pw', async (req, res) => {
    const { targetId, newPw } = req.body;
    try {
        await pool.query(`
            INSERT INTO passwords (student_id, password_hash) VALUES (?, ?)
            ON DUPLICATE KEY UPDATE password_hash = ?
        `, [targetId, newPw, newPw]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: '비밀번호 강제 변경 에러' });
    }
});

// [ADMIN API] 오픈 일시 전역 변수 설정 락커
app.post('/api/admin/set-opentime', async (req, res) => {
    const { openTime } = req.body;
    try {
        await pool.query("INSERT INTO system_config (cfg_key, cfg_value) VALUES ('open_time', ?) ON DUPLICATE KEY UPDATE cfg_value = ?", [openTime, openTime]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: '오픈 시간 변경 실패' });
    }
});

// [ADMIN API] 예약 테이블 전면 공백 초기화 통제
app.post('/api/admin/clear-reservations', async (req, res) => {
    try {
        await pool.query("TRUNCATE TABLE reservations;");
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: '예약 전면 포맷 초기화 실패' });
    }
});

// [ADMIN API] 필터 금지 단어 어레이 배열 직렬화 동기화
app.post('/api/admin/set-censored', async (req, res) => {
    const { words } = req.body;
    try {
        const filtered = words.filter(w => w.trim().length > 0);
        const jsonStr = JSON.stringify(filtered);
        await pool.query("INSERT INTO system_config (cfg_key, cfg_value) VALUES ('censored_words', ?) ON DUPLICATE KEY UPDATE cfg_value = ?", [jsonStr, jsonStr]);
        res.json({ success: true, count: filtered.length });
    } catch (err) {
        res.status(500).json({ message: '금지어 수립 실패' });
    }
});

// [ADMIN API] 귓속말 민원 전수 검사 보드
app.post('/api/admin/whispers-box', async (req, res) => {
    try {
        const [rows] = await pool.query(`
            SELECT w.student_id as studentId, sm.name, w.content as text, 
                   DATE_FORMAT(w.created_at, '%Y-%m-%d %H:%i') as time
            FROM whispers w
            JOIN student_master sm ON w.student_id = sm.student_id
            ORDER BY w.id DESC
        `);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ message: '귓속말 수신 보드 로딩 실패' });
    }
});
// [PUBLIC API] 오늘의 야자 감독관 이름 조회 (학생 및 관리자 공통 호출 권한)
app.get('/api/supervisor', async (req, res) => {
    try {
        const [rows] = await pool.query("SELECT cfg_value FROM system_config WHERE cfg_key = 'supervisor_name'");
        const name = rows.length > 0 ? rows[0].cfg_value : "";
        res.json({ supervisorName: name });
    } catch (err) {
        res.status(500).json({ message: '야자 감독 정보 조회 중 내부 서버 오류가 발생했습니다.' });
    }
});

// [ADMIN API] 오늘의 야자 감독관 이름 저장 및 실시간 업데이트 (JWT 토큰 기반 제로 트러스트 검증 필수)
app.post('/api/admin/supervisor', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: '인증 토큰이 제공되지 않았습니다.' });
    }

    try {
        // 복호화 및 유효 토큰 기밀성 검사
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // F12 개발자 도구 위조 우회 테러 방어: 오직 studentId 가 고유 관리자 계정('salesio')인 경우에만 인가 처리
        if (decoded.studentId !== 'salesio') {
            return res.status(403).json({ message: '접근 권한이 없습니다. 최고 보안 관리자 전용 기능입니다.' });
        }

        const { supervisorName } = req.body;
        // 입력되지 않은 상태로 전송될 시 완벽하게 빈칸 처리를 유지하기 위해 예외 대입 구조 매핑
        const savedValue = (supervisorName && supervisorName.trim() !== "") ? supervisorName.trim() : "";

        await pool.query("UPDATE system_config SET cfg_value = ? WHERE cfg_key = 'supervisor_name'", [savedValue]);
        res.json({ success: true, message: '오늘의 야자 감독 데이터가 서버에 정상 기록되었습니다.' });
    } catch (err) {
        res.status(403).json({ message: '만료되었거나 위조된 서명 토큰입니다.' });
    }
});
// [ADMIN API] 출결 상태 즉시 반영 및 토글 엔진 (보안 최우선)
app.post('/api/admin/attendance-toggle', async (req, res) => {
    const { studentId, currentStatus } = req.body;
    if (!studentId) return res.status(400).json({ message: '학번 데이터가 유실되었습니다.' });
    
    const todayStr = new Date().toISOString().split('T')[0];
    const nextStatus = currentStatus === 'ATTEND' ? 'RESERVED' : 'ATTEND';

    try {
        await pool.query(`
            INSERT INTO attendance_noshow (student_id, type, date)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE type = ?
        `, [studentId, nextStatus, todayStr, nextStatus]);

        res.json({ success: true, nextStatus, message: '출결 상태가 안전하게 업데이트되었습니다.' });
    } catch (err) {
        console.error("출결 토글 오류:", err);
        res.status(500).json({ message: '출결 처리 중 서버 내부 데이터베이스 충돌이 발생했습니다.' });
    }
});

// [ADMIN API] 특정 좌석의 특이사항 상태 업데이트 라우터
app.post('/api/admin/attendance-action', async (req, res) => {
    const { studentId, actionType } = req.body;
    if (!studentId || !actionType) return res.status(400).json({ message: '필수 파라미터가 유실되었습니다.' });

    const todayStr = new Date().toISOString().split('T')[0];

    try {
        // 1. 출결 이력 테이블 업데이트
        await pool.query(`
            INSERT INTO attendance_noshow (student_id, type, date)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE type = ?
        `, [studentId, actionType, todayStr, actionType]);

        // 2. 만약 노쇼 경고 부여인 경우 누적 이력 테이블에 별도 기록 파이프라인 가동
        if (actionType === 'NOSHOW_WARN') {
            const [studentRows] = await pool.query("SELECT name FROM student_master WHERE student_id = ?", [studentId]);
            const studentName = studentRows.length > 0 ? studentRows[0].name : "미등록학생";
            
            // 학년/반 파싱 (학번 앞 3자리 기준 보정 예시: 1학년 1반 -> 101)
            let gradeClass = "미분류";
            if (studentId.length >= 3) {
                gradeClass = studentId.substring(0, 3);
            }

            await pool.query(`
                INSERT INTO noshow_warnings (student_id, student_name, grade_class, reason)
                VALUES (?, ?, ?, ?)
            `, [studentId, studentName, gradeClass, '자습실 무단 불참 및 노쇼 시스템 자동 부여']);
        }

        res.json({ success: true, message: '행정 조치 상태가 서버에 정상 기록되었습니다.' });
    } catch (err) {
        console.error("출결 조치 에러:", err);
        res.status(500).json({ message: '행정 조치 처리 중 데이터 영속화 실패.' });
    }
});

// [ADMIN API] 반별 노쇼 경고 히스토리 대시보드 데이터 공급 포트
app.get('/api/admin/noshow-history', async (req, res) => {
    const { gradeClass } = req.query;
    if (!gradeClass) return res.status(400).json({ message: '조회 대상 학년/반 코드가 없습니다.' });

    try {
        // 학년/반에 해당하는 학생들의 전체 경고 이력 및 통계 서브쿼리 연동
        const [rows] = await pool.query(`
            SELECT 
                w.student_id, 
                w.student_name, 
                w.warning_date, 
                w.reason,
                (SELECT COUNT(*) FROM noshow_warnings WHERE student_id = w.student_id) as total_count
            FROM noshow_warnings w
            WHERE w.grade_class = ?
            ORDER BY w.warning_date DESC
        `, [gradeClass]);

        res.json(rows);
    } catch (err) {
        console.error("히스토리 쿼리 에러:", err);
        res.status(500).json({ message: '대시보드 데이터를 조회하는 데 실패했습니다.' });
    }
});

// [API Expansion] 기존 /api/status 에서 출결 현황 상태를 함께 서빙하도록 보완 피팅
// [ADMIN API] 익명 댓글 저자 기밀 역추적 시스템
app.post('/api/admin/trace-comment', async (req, res) => {
    const { commentId } = req.body;
    try {
        const [rows] = await pool.query(`
            SELECT c.student_id, sm.name FROM comments c
            JOIN student_master sm ON c.student_id = sm.student_id
            WHERE c.id = ?
        `, [commentId]);

        if (rows.length === 0) return res.status(444).json({ message: '존재하지 않는 글' });

        res.json({
            success: true,
            studentId: rows[0].student_id,
            name: rows[0].name
        });
    } catch (err) {
        res.status(500).json({ message: '익명 저자 역추적 서버 실패' });
    }
});

app.listen(PORT, () => {
    console.log(`🚀 [Server] 외부 DB 커넥티드 통합 서버 가동 포트: ${PORT}`);
});