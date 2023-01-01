### postman screenshot

0.memberIdPw  
-> 사용할 아이디와 비밀번호

1.index
-> 별도의 인증 절차가 필요하지 않은 메인 페이지

2.login(admin)  
-> admin 계정으로 로그인, 만들어진 토큰

3.user(admin)  
-> admin 계정으로 로그인한 상태로(admin의 accessToken 이용) /user 접속, 성공

4.admin(admin)  
-> admin 계정으로 로그인한 상태로(admin의 accessToken 이용) /admin 접속, 성공

5.login(user)  
-> user 계정으로 로그인, 만들어진 토큰

6.user(user)  
-> user 계정으로 로그인한 상태로(user accessToken 이용) /user 접속, 성공

7.admin(user)  
-> user 계정으로 로그인한 상태로(user accessToken 이용) /admin 접속, 실패

8.test(success)  
-> user 계정(아무 계정이나 상관 없음)으로 로그인한 상태로(accessToken 이용) /test 접속, 성공

9.test(forbidden)  
-> accessToken 없는 상태로(인증 없음) /test 접속, 실패
