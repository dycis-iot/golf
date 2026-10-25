-- PINHIGH 홀인원 기금 원자적 거래 함수
-- Supabase SQL Editor에서 운영진이 내용을 검토한 후 한 번 실행하세요.
-- 전제: public.admins(auth_user_id,role,active), meetings, meeting_participants, hole_in_one_transactions.
-- 관리자(super/accounting) 외 호출 불가. 클라이언트는 SECURITY DEFINER RPC만 사용.
create or replace function public.pinhigh_fund_contribution(p_meeting uuid, p_member uuid)
returns numeric language plpgsql security definer set search_path=public
as $$
declare v_role text; v_existing boolean; v_status text;
begin
 select role::text into v_role from public.admins where auth_user_id=auth.uid() and active=true limit 1;
 if v_role not in ('super','accounting') or v_role is null then raise exception '기금 납부 권한이 없습니다'; end if;
 perform pg_advisory_xact_lock(hashtextextended('pinhigh_fund',0));
 select status into v_status from public.meetings where id=p_meeting;
 if v_status is null then raise exception '정모가 없습니다'; end if;
 if v_status='completed' and v_role<>'super' then raise exception '완료된 정모는 최고관리자만 수정할 수 있습니다'; end if;
 if not exists(select 1 from public.meeting_participants where meeting_id=p_meeting and member_id=p_member)
 then raise exception '정모 신청자가 아닙니다'; end if;
 select exists(select 1 from public.hole_in_one_transactions where meeting_id=p_meeting and member_id=p_member and type='contribution') into v_existing;
 if v_existing then raise exception '이미 납부 기록이 있습니다'; end if;
 insert into public.hole_in_one_transactions(type,amount,occurred_at,member_id,meeting_id,note)
 values('contribution',2000,now(),p_member,p_meeting,'정모 홀인원 기금 납부');
 update public.meeting_participants set payment_status='paid',updated_at=now() where meeting_id=p_meeting and member_id=p_member;
 return 2000;
end $$;
create or replace function public.pinhigh_fund_payout(p_member uuid,p_date date)
returns numeric language plpgsql security definer set search_path=public
as $$
declare v_role text; v_balance numeric; v_amount numeric;
begin
 select role::text into v_role from public.admins where auth_user_id=auth.uid() and active=true limit 1;
 if v_role not in ('super','accounting') or v_role is null then raise exception '기금 지급 권한이 없습니다'; end if;
 if p_date is null or p_date>current_date then raise exception '올바른 발생일을 입력해 주세요'; end if;
 if not exists(select 1 from public.members where id=p_member) then raise exception '등록된 회원이 아닙니다'; end if;
 perform pg_advisory_xact_lock(hashtextextended('pinhigh_fund',0));
 select coalesce(sum(case when type='payout' then -amount else amount end),0) into v_balance from public.hole_in_one_transactions;
 v_amount=floor(greatest(v_balance,0)/2);
 if v_amount<=0 then raise exception '지급 가능한 기금이 없습니다'; end if;
 insert into public.hole_in_one_transactions(type,amount,occurred_at,member_id,note)
 values('payout',v_amount,(p_date::timestamp + interval '12 hours') at time zone 'Asia/Seoul',p_member,'홀인원 50% 지급 · 중복 등록 전 거래내역 확인');
 return v_amount;
end $$;
-- 초기 잔액은 최초 1회만 적용, 최고관리자 전용.
create or replace function public.pinhigh_fund_opening(p_amount numeric)
returns numeric language plpgsql security definer set search_path=public
as $$
declare v_role text;
begin
 select role::text into v_role from public.admins where auth_user_id=auth.uid() and active=true limit 1;
 if v_role is distinct from 'super' then raise exception '최고관리자만 초기 이월을 등록할 수 있습니다'; end if;
 if p_amount is null or p_amount<0 or p_amount<>floor(p_amount) then raise exception '금액은 0 이상의 정수여야 합니다'; end if;
 perform pg_advisory_xact_lock(hashtextextended('pinhigh_fund',0));
 if exists(select 1 from public.hole_in_one_transactions where type='adjustment' and note='PINHIGH 초기 이월 기금') then raise exception '이미 초기 이월 기금이 등록되어 있습니다'; end if;
 insert into public.hole_in_one_transactions(type,amount,occurred_at,note) values('adjustment',p_amount,now(),'PINHIGH 초기 이월 기금');
 return p_amount;
end $$;
revoke all on function public.pinhigh_fund_contribution(uuid,uuid) from public,anon;
revoke all on function public.pinhigh_fund_payout(uuid,date) from public,anon;
revoke all on function public.pinhigh_fund_opening(numeric) from public,anon;
grant execute on function public.pinhigh_fund_contribution(uuid,uuid) to authenticated;
grant execute on function public.pinhigh_fund_payout(uuid,date) to authenticated;
grant execute on function public.pinhigh_fund_opening(numeric) to authenticated;
