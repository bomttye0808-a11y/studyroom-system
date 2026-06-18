const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// 보안 강화: 환경변수가 없을 경우 기본 마스터 비밀번호 설정
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'salesioadmin15130!';

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// 가상 파일 DB 경로 지정
const DB_PATH = path.join(__dirname, 'database.json');

// 시스템 통합 영속성 데이터셋 기본 구조 초기화
function initDatabase() {
    if (!fs.existsSync(DB_PATH)) {
        const initialSchema = {
            studentMaster: {}, // 요구사항 반영: 초기 로드 시점 완전 빈 객체로 초기화
            passwords: {},
            reservations: {},
            comments: [],
            openTime: "",
            censoredWords: [],
            whispers: []
        };
        fs.writeFileSync(DB_PATH, JSON.stringify(initialSchema, null, 4), 'utf8');
    } else {
        // 기존 파일이 존재하더라도 스키마 유실 대비 안전 확인
        try {
            const data = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
            let updated = false;
            if (!data.studentMaster) { data.studentMaster = {}; updated = true; }
            if (!data.passwords) { data.passwords = {}; updated = true; }
            if (!data.reservations) { data.reservations = {}; updated = true; }
            if (!data.comments) { data.comments = []; updated = true; }
            if (!data.openTime) { data.openTime = ""; updated = true; }
            if (!data.censoredWords) { data.censoredWords = []; updated = true; }
            if (!data.whispers) { data.whispers = []; updated = true; }
            if (updated) fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 4), 'utf8');
        } catch (e) {
            console.error("DB 로드 에러, 초기화 진행");
        }
    }
}
initDatabase();

// DB 헬퍼 함수
function readDB() {
    return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
}
function writeDB(data) {
    fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 4), 'utf8');
}

// 텍스트 필터링 마스킹 엔진 함수
function applyCensorship(text, words) {
    if (!text || !words || words.length === 0) return text;
    let censored = text;
    words.forEach(word => {
        if (!word.trim()) return;
        const regex = new RegExp(word.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&'), 'gi');
        censored = censored.replace(regex, '*'.repeat(word.length));
    });
    return censored;
}

// 유저별 고정 익명 번호 부여 알고리즘
function getAnonymousId(studentId, commentsList) {
    const userComments = commentsList.filter(c => c.writer === studentId);
    if (userComments.length > 0) {
        return userComments[0].anonName;
    }
    const maxAnonNum = commentsList.reduce((max, c) => {
        const num = parseInt(c.anonName.replace('익명', ''), 10);
        return (!isNaN(num) && num > max) ? num : max;
    }, 0);
    return `익명${maxAnonNum + 1}`;
}

// [API] 실시간 폴링용 상태 조회
app.get('/api/status', (req, res) => {
    const db = readDB();
    res.json({
        reservations: db.reservations,
        openTime: db.openTime,
        commentsCount: db.comments.length
    });
});

// [API] 로그인 검증 엔진
app.post('/api/login', (req, res) => {
    const { studentId, password } = req.body;
    const db = readDB();

    // 특수 행정용 관리자 계정 처리
    if (studentId === 'salesio' && password === ADMIN_PASSWORD) {
        return res.json({ success: true, isAdmin: true, name: '관리자' });
    }

    if (!db.studentMaster[studentId]) {
        return res.status(400).json({ success: false, message: '등록되지 않은 학번입니다.' });
    }

    const savedPw = db.passwords[studentId];
    if (!savedPw) {
        // 최초 로그인 비밀번호 등록 바인딩
        if (password && password.length === 4 && !isNaN(password)) {
            db.passwords[studentId] = password;
            writeDB(db);
            return res.json({ success: true, isAdmin: false, name: db.studentMaster[studentId] });
        } else {
            return res.status(400).json({ success: false, message: '최초 비밀번호는 숫자 4자리여야 합니다.' });
        }
    } else {
        if (savedPw !== password) {
            return res.status(400).json({ success: false, message: '학번/비밀번호가 일치하지 않습니다.' });
        }
        return res.json({ success: true, isAdmin: false, name: db.studentMaster[studentId] });
    }
});

// [API] 실시간 실명 조회 엔드포인트
app.get('/api/student-check/:id', (req, res) => {
    const db = readDB();
    const studentId = req.params.id;
    if (db.studentMaster[studentId]) {
        const isRegistered = !!db.passwords[studentId];
        res.json({ exists: true, name: db.studentMaster[studentId], isRegistered });
    } else {
        res.json({ exists: false });
    }
});

// [API] 단일 트랜잭션 원터치 좌석 스와핑 예약 처리 엔진
app.post('/api/reserve', (req, res) => {
    const { studentId, day, roomType, seatId } = req.body;
    const db = readDB();

    // 시간 통제 락킹 확인
    if (!db.openTime) return res.status(403).json({ message: '아직 예약 시간이 아닙니다.' });
    if (new Date(db.openTime) > new Date()) return res.status(403).json({ message: '아직 예약 시간이 아닙니다.' });

    if (!db.reservations[day]) db.reservations[day] = {};

    // 동일 요일 기존 선점 예약 내역 파기 및 변경 트랜잭션
    let canceledSeat = null;
    for (const seat in db.reservations[day]) {
        if (db.reservations[day][seat].studentId === studentId) {
            canceledSeat = seat;
            delete db.reservations[day][seat];
        }
    }

    if (db.reservations[day][seatId]) {
        return res.status(400).json({ message: '이미 선점된 좌석입니다.' });
    }

    // 신규 배정 등록 일괄 커밋
    db.reservations[day][seatId] = { studentId, roomType, name: db.studentMaster[studentId] };
    writeDB(db);
    res.json({ success: true, canceledSeat, newSeat: seatId });
});

// [API] 예약 단건 취소
app.post('/api/cancel', (req, res) => {
    const { studentId, day, seatId } = req.body;
    const db = readDB();
    if (db.reservations[day] && db.reservations[day][seatId] && db.reservations[day][seatId].studentId === studentId) {
        delete db.reservations[day][seatId];
        writeDB(db);
        return res.json({ success: true });
    }
    res.status(400).json({ message: '취소 권한이 없거나 유효하지 않은 좌석입니다.' });
});

// [API] 댓글/대댓글 및 게시판 가져오기 (마스킹 정제 처리)
app.get('/api/comments', (req, res) => {
    const db = readDB();
    res.json({
        notice: db.notice || "",
        comments: db.comments
    });
});

// [API] 공지사항 수정 (관리자 전용)
app.post('/api/admin/notice', (req, res) => {
    const { password, text } = req.body;
    if (password !== ADMIN_PASSWORD) return res.status(401).json({ message: '인증에 실패했습니다.' });
    const db = readDB();
    db.notice = text;
    writeDB(db);
    res.json({ success: true });
});

// [API] 댓글 등록 엔진 (트리 계정 지원)
app.post('/api/comments/add', (req, res) => {
    const { studentId, text, parentId } = req.body;
    const db = readDB();
    if (!db.studentMaster[studentId]) return res.status(403).json({ message: '권한이 없습니다.' });

    const filteredText = applyCensorship(text, db.censoredWords);
    const anonName = getAnonymousId(studentId, db.comments);
    const now = new Date();
    const dateStr = `${String(now.getMonth() + 1).padStart(2, '0')}/${String(now.getDate()).padStart(2, '0')} ${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;

    const newComment = {
        id: 'c_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
        parentId: parentId || null,
        writer: studentId,
        anonName: anonName,
        text: filteredText,
        date: dateStr,
        likes: []
    };

    db.comments.push(newComment);
    writeDB(db);
    res.json({ success: true, comment: newComment });
});

// [API] 댓글 수정 및 삭제 권한 필터
app.post('/api/comments/edit', (req, res) => {
    const { commentId, studentId, text } = req.body;
    const db = readDB();
    const target = db.comments.find(c => c.id === commentId);
    if (!target || target.writer !== studentId) return res.status(403).json({ message: '수정 권한이 없습니다.' });

    target.text = applyCensorship(text, db.censoredWords);
    writeDB(db);
    res.json({ success: true });
});

app.post('/api/comments/delete', (req, res) => {
    const { commentId, studentId } = req.body;
    const db = readDB();
    const index = db.comments.findIndex(c => c.id === commentId);
    if (index === -1 || db.comments[index].writer !== studentId) return res.status(403).json({ message: '삭제 권한이 없습니다.' });

    db.comments.splice(index, 1);
    writeDB(db);
    res.json({ success: true });
});

// [API] 좋아요 토글
app.post('/api/comments/like', (req, res) => {
    const { commentId, studentId } = req.body;
    const db = readDB();
    const target = db.comments.find(c => c.id === commentId);
    if (!target) return res.status(444).json({ message: '댓글이 존재하지 않습니다.' });

    const pos = target.likes.indexOf(studentId);
    if (pos === -1) target.likes.push(studentId);
    else target.likes.splice(pos, 1);

    writeDB(db);
    res.json({ success: true, likesCount: target.likes.length });
});

// [API] 귓속말 1:1 메시지 발신 및 내역 조회
app.post('/api/whisper/send', (req, res) => {
    const { studentId, text } = req.body;
    const db = readDB();
    if (!db.studentMaster[studentId]) return res.status(403).json({ message: '인증 실패' });

    const now = new Date();
    const timeStr = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-${String(now.getDate()).padStart(2,'0')} ${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}`;
    
    db.whispers.push({
        studentId,
        name: db.studentMaster[studentId],
        text,
        time: timeStr
    });
    writeDB(db);
    res.json({ success: true });
});

app.get('/api/whisper/my/:id', (req, res) => {
    const db = readDB();
    const myWhispers = db.whispers.filter(w => w.studentId === req.params.id);
    res.json(myWhispers);
});

// [ADMIN API] 엑셀 대용량 학생 마스터 구조 데이터 일괄 빌드 업로드
app.post('/api/admin/upload-students', (req, res) => {
    const { password, students } = req.body;
    if (password !== ADMIN_PASSWORD) return res.status(401).json({ message: '인증 실패' });
    const db = readDB();

    students.forEach(s => {
        if (s.학번 && s.이름) {
            db.studentMaster[String(s.학번).trim()] = String(s.이름).trim();
        }
    });

    writeDB(db);
    res.json({ success: true, count: Object.keys(db.studentMaster).length });
});

// [ADMIN API] 학생 정보 인라인 마스터 테이블 조회 및 강제 변경
app.post('/api/admin/students-list', (req, res) => {
    const { password } = req.body;
    if (password !== ADMIN_PASSWORD) return res.status(401).json({ message: '인증 실패' });
    const db = readDB();
    const list = Object.keys(db.studentMaster).map(id => ({
        studentId: id,
        name: db.studentMaster[id],
        password: db.passwords[id] || null
    }));
    res.json(list);
});

app.post('/api/admin/change-student-pw', (req, res) => {
    const { password, targetId, newPw } = req.body;
    if (password !== ADMIN_PASSWORD) return res.status(401).json({ message: '인증 실패' });
    const db = readDB();
    db.passwords[targetId] = newPw;
    writeDB(db);
    res.json({ success: true });
});

// [ADMIN API] 오픈 일시 갱신
app.post('/api/admin/set-opentime', (req, res) => {
    const { password, openTime } = req.body;
    if (password !== ADMIN_PASSWORD) return res.status(401).json({ message: '인증 실패' });
    const db = readDB();
    db.openTime = openTime;
    writeDB(db);
    res.json({ success: true });
});

// [ADMIN API] 통합 예약 전면 초기화
app.post('/api/admin/clear-reservations', (req, res) => {
    const { password } = req.body;
    if (password !== ADMIN_PASSWORD) return res.status(401).json({ message: '인증 실패' });
    const db = readDB();
    db.reservations = {};
    writeDB(db);
    res.json({ success: true });
});

// [ADMIN API] 금지 단어 텍스트 파일 실시간 동기화
app.post('/api/admin/set-censored', (req, res) => {
    const { password, words } = req.body;
    if (password !== ADMIN_PASSWORD) return res.status(401).json({ message: '인증 실패' });
    const db = readDB();
    db.censoredWords = words.filter(w => w.trim().length > 0);
    writeDB(db);
    res.json({ success: true, count: db.censoredWords.length });
});

// [ADMIN API] 귓속말 수신함 전체 조회
app.post('/api/admin/whispers-box', (req, res) => {
    const { password } = req.body;
    if (password !== ADMIN_PASSWORD) return res.status(401).json({ message: '인증 실패' });
    const db = readDB();
    res.json(db.whispers || []);
});

// [ADMIN API] 익명 댓글 역추적 시스템 엔드포인트
app.post('/api/admin/trace-comment', (req, res) => {
    const { password, commentId } = req.body;
    if (password !== ADMIN_PASSWORD) return res.status(401).json({ message: '인증 실패' });
    const db = readDB();
    const target = db.comments.find(c => c.id === commentId);
    if (!target) return res.status(444).json({ message: '존재하지 않는 글' });

    res.json({
        success: true,
        studentId: target.writer,
        name: db.studentMaster[target.writer] || '미등록 학적'
    });
});

app.listen(PORT, () => {
    console.log(`서버 정상 가동포트: ${PORT}`);
});