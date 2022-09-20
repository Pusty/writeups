define i64 @f() #1  {
entry:
    %some = add i64 0, 42
    br label %middle
middle:
    %o0 = or i64 %some, 5

    %q2 = mul i64 %o0, 7
    %q1 = sdiv i64 %q2, 34
    %q0 = add i64 %q1, 37

    %p2 = mul i64 %some, 66
    %p1 = sdiv i64 %p2, 27
    %p0 = add i64 %p1, 80

    %v  = mul i64 %p0, %q0

    br label %end
end:
    ret i64 %v
}

attributes #1 = { noinline nounwind optnone ssp uwtable }

