#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
كتيب إرشادات نظام مكتب المحامي هشام يوسف الخياط
"""

from fpdf import FPDF
from fpdf.enums import XPos, YPos
import os

class ArabicPDF(FPDF):
    def __init__(self):
        super().__init__()
        # تحميل الخط العربي Noto Sans Arabic
        regular_font = "/app/backend/fonts/NotoSansArabic-Regular.ttf"
        bold_font = "/app/backend/fonts/NotoSansArabic-Bold.ttf"
        
        if os.path.exists(regular_font):
            self.add_font("Arabic", "", regular_font)
        if os.path.exists(bold_font):
            self.add_font("Arabic", "B", bold_font)
        
        # Enable text shaping immediately
        self.set_text_shaping(True)
    
    def header(self):
        self.set_font('Arabic', '', 10)
        self.set_text_color(100, 100, 100)
        self.cell(0, 10, 'مكتب المحامي هشام يوسف الخياط - دليل المستخدم', new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
        self.ln(5)
        self.set_x(self.l_margin)  # Reset X position
    
    def footer(self):
        self.set_y(-15)
        self.set_font('Arabic', '', 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f'صفحة {self.page_no()}', align='C')
    
    def chapter_title(self, title):
        self.set_font('Arabic', 'B', 16)
        self.set_fill_color(30, 58, 95)
        self.set_text_color(255, 255, 255)
        self.set_x(self.l_margin)
        self.cell(0, 12, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C', fill=True)
        self.ln(5)
        self.set_text_color(0, 0, 0)
        self.set_x(self.l_margin)
    
    def section_title(self, title):
        self.set_font('Arabic', 'B', 14)
        self.set_text_color(30, 58, 95)
        self.set_x(self.l_margin)
        self.cell(0, 10, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
        self.set_text_color(0, 0, 0)
        self.ln(2)
        self.set_x(self.l_margin)
    
    def body_text(self, text):
        self.set_font('Arabic', '', 11)
        self.set_x(self.l_margin)
        self.multi_cell(0, 7, text, align='J')
        self.ln(3)
        self.set_x(self.l_margin)
    
    def bullet_point(self, text):
        self.set_font('Arabic', '', 11)
        self.set_x(self.l_margin)
        self.multi_cell(0, 7, f'{text}  -', align='R')
    
    def info_box(self, title, content):
        self.set_fill_color(240, 248, 255)
        self.set_draw_color(30, 58, 95)
        self.rect(10, self.get_y(), 190, 30, 'DF')
        self.set_font('Arabic', 'B', 10)
        self.set_xy(15, self.get_y() + 5)
        self.cell(180, 6, title, align='C')
        self.ln(8)
        self.set_x(15)
        self.set_font('Arabic', '', 9)
        self.multi_cell(180, 5, content, align='C')
        self.ln(15)

def create_manual():
    pdf = ArabicPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_left_margin(10)
    pdf.set_right_margin(10)
    
    # === صفحة الغلاف ===
    pdf.add_page()
    pdf.ln(40)
    pdf.set_font('Arabic', 'B', 28)
    pdf.set_text_color(30, 58, 95)
    pdf.cell(0, 20, 'دليل المستخدم', new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
    pdf.ln(10)
    pdf.set_font('Arabic', '', 18)
    pdf.set_text_color(184, 157, 92)
    pdf.cell(0, 15, 'نظام إدارة مكتب المحاماة', new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
    pdf.ln(20)
    pdf.set_font('Arabic', '', 14)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 10, 'مكتب المحامي هشام يوسف الخياط', new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
    pdf.ln(40)
    pdf.set_font('Arabic', '', 10)
    pdf.cell(0, 8, 'الإصدار 1.0 - 2025', new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
    
    # === فهرس المحتويات ===
    pdf.add_page()
    pdf.chapter_title('فهرس المحتويات')
    pdf.ln(5)
    
    contents = [
        '1. مقدمة عن النظام',
        '2. تسجيل الدخول',
        '3. لوحة تحكم المدير',
        '4. إدارة طلبات العملاء',
        '5. نظام الإحالة والمهام',
        '6. نظام الحضور والانصراف',
        '7. التقارير',
        '8. نظام البريد الداخلي',
        '9. لوحة تحكم المسوق',
        '10. بوابة العميل',
        '11. التواصل عبر واتساب',
        '12. الدعم الفني',
    ]
    
    for item in contents:
        pdf.set_font('Arabic', '', 12)
        pdf.cell(0, 10, item, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='L')
    
    # === 1. مقدمة ===
    pdf.add_page()
    pdf.chapter_title('1. مقدمة عن النظام')
    
    pdf.body_text('نظام إدارة مكتب المحاماة هو نظام متكامل مصمم خصيصاً لمكتب المحامي هشام يوسف الخياط لإدارة جميع العمليات القانونية والإدارية بكفاءة عالية.')
    
    pdf.section_title('أنواع المستخدمين')
    pdf.bullet_point('المدير (Admin): تحكم كامل في جميع وظائف النظام')
    pdf.bullet_point('المحامي (Lawyer): إدارة القضايا والاستشارات')
    pdf.bullet_point('المحاسب (Accountant): إدارة الشؤون المالية')
    pdf.bullet_point('الموظف (Staff): مهام إدارية عامة')
    pdf.bullet_point('المسوق (Marketer): إدارة العملاء المحتملين والعروض')
    pdf.bullet_point('العميل (Client): متابعة القضايا والطلبات')
    
    pdf.ln(5)
    pdf.section_title('المميزات الرئيسية')
    pdf.bullet_point('إدارة القضايا والاستشارات وخدمات الموثق')
    pdf.bullet_point('نظام إحالة المهام بين الموظفين')
    pdf.bullet_point('تتبع الحضور والانصراف مع تحديد الموقع')
    pdf.bullet_point('التواصل عبر واتساب مع العملاء')
    pdf.bullet_point('نظام الإشعارات والبريد الداخلي')
    pdf.bullet_point('تقارير شاملة وإحصائيات')
    
    # === 2. تسجيل الدخول ===
    pdf.add_page()
    pdf.chapter_title('2. تسجيل الدخول')
    
    pdf.body_text('للدخول إلى النظام، اتبع الخطوات التالية:')
    pdf.ln(3)
    pdf.bullet_point('1. افتح متصفح الإنترنت وانتقل إلى رابط النظام')
    pdf.bullet_point('2. أدخل البريد الإلكتروني وكلمة المرور')
    pdf.bullet_point('3. اضغط على زر "تسجيل الدخول"')
    
    pdf.ln(5)
    pdf.section_title('حسابات الدخول')
    
    pdf.set_font('Arabic', '', 10)
    pdf.set_fill_color(240, 240, 240)
    
    # جدول الحسابات
    col_width = 60
    pdf.cell(col_width, 10, 'الدور', border=1, align='C', fill=True)
    pdf.cell(col_width, 10, 'البريد الإلكتروني', border=1, align='C', fill=True)
    pdf.cell(col_width, 10, 'كلمة المرور', border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C', fill=True)
    
    accounts = [
        ('المدير', 'hesham@hklaw.sa', 'alkhayat2025'),
        ('المسوق', 'ahmed@hklaw.sa', 'temp123'),
        ('محامي', 'shami@hklaw.sa', 'temp123'),
    ]
    
    for role, email, pwd in accounts:
        pdf.cell(col_width, 10, role, border=1, align='C')
        pdf.cell(col_width, 10, email, border=1, align='C')
        pdf.cell(col_width, 10, pwd, border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
    
    pdf.ln(10)
    pdf.info_box('ملاحظة هامة:', 'يُنصح بتغيير كلمة المرور عند أول تسجيل دخول للحفاظ على أمان الحساب.')
    
    # === 3. لوحة تحكم المدير ===
    pdf.add_page()
    pdf.chapter_title('3. لوحة تحكم المدير')
    
    pdf.body_text('لوحة تحكم المدير هي الواجهة الرئيسية التي تعرض نظرة شاملة على جميع عمليات المكتب.')
    
    pdf.section_title('الإحصائيات المعروضة')
    pdf.bullet_point('إجمالي القضايا: جديدة، تحت الإجراء، منتهية')
    pdf.bullet_point('إجمالي الاستشارات: جديدة، تحت الإجراء، منتهية')
    pdf.bullet_point('استشارات الزوار: جديدة، تحت الإجراء، منتهية')
    pdf.bullet_point('خدمات الموثق: جديدة، تحت الإجراء، منتهية')
    pdf.bullet_point('إحصائيات المهام: من العملاء، من الموظفين')
    
    pdf.ln(3)
    pdf.section_title('المتواجدين حالياً')
    pdf.bullet_point('الموظفين المتواجدين: يظهر من سجل حضور ولم يسجل انصراف')
    pdf.bullet_point('العملاء المتصلين: يظهر من نشط خلال آخر 15 دقيقة')
    
    pdf.ln(3)
    pdf.section_title('جدول حضور اليوم')
    pdf.body_text('يعرض سجل حضور جميع الموظفين لليوم الحالي مع:')
    pdf.bullet_point('وقت الدخول وموقع الدخول')
    pdf.bullet_point('وقت الخروج وموقع الخروج')
    pdf.bullet_point('حالة الموظف (متواجد/انصرف)')
    pdf.bullet_point('إجمالي ساعات العمل')
    
    pdf.ln(3)
    pdf.section_title('تنبيهات الحضور')
    pdf.body_text('يظهر تنبيه أصفر في أعلى الصفحة عندما:')
    pdf.bullet_point('يتأخر موظف عن الحضور (بعد 15 دقيقة من بداية الدوام)')
    pdf.bullet_point('يتجاوز موظف وقت العمل المحدد')
    pdf.bullet_point('ينسى موظف تسجيل الانصراف')
    
    # === 4. إدارة طلبات العملاء ===
    pdf.add_page()
    pdf.chapter_title('4. إدارة طلبات العملاء')
    
    pdf.body_text('صفحة طلبات العملاء تعرض جميع الطلبات الواردة من العملاء مقسمة إلى ثلاثة أقسام:')
    
    pdf.section_title('تبويب القضايا')
    pdf.body_text('يعرض جميع طلبات القضايا المرسلة من العملاء مع:')
    pdf.bullet_point('رقم الطلب واسم العميل ورقم الجوال')
    pdf.bullet_point('موضوع القضية وتاريخ التقديم')
    pdf.bullet_point('حالة الطلب والموظف المحال إليه')
    
    pdf.section_title('تبويب الاستشارات')
    pdf.body_text('يعرض طلبات الاستشارات القانونية من العملاء المسجلين.')
    
    pdf.section_title('تبويب خدمات الموثق')
    pdf.body_text('يعرض طلبات خدمات التوثيق مثل:')
    pdf.bullet_point('توثيق العقود')
    pdf.bullet_point('الوكالات الشرعية')
    pdf.bullet_point('الإقرارات')
    
    pdf.ln(3)
    pdf.section_title('إجراءات متاحة لكل طلب')
    pdf.bullet_point('عرض التفاصيل: لرؤية كافة معلومات الطلب')
    pdf.bullet_point('إجراء/إحالة: لتسجيل إجراء أو إحالة لموظف')
    pdf.bullet_point('واتساب: للتواصل المباشر مع العميل')
    
    # === 5. نظام الإحالة ===
    pdf.add_page()
    pdf.chapter_title('5. نظام الإحالة والمهام')
    
    pdf.body_text('نظام الإحالة يسمح بتوزيع المهام بين الموظفين وتتبع سير العمل.')
    
    pdf.section_title('أنواع الإجراءات')
    pdf.bullet_point('تحديث حالة: لتغيير حالة الطلب فقط')
    pdf.bullet_point('إحالة لموظف: لتحويل الطلب لموظف واحد أو أكثر')
    pdf.bullet_point('نقل للإدارة: لتحويل الطلب للمدير')
    pdf.bullet_point('حفظ بالأرشيف: لأرشفة الطلب بعد الانتهاء')
    
    pdf.section_title('خطوات إضافة إجراء')
    pdf.bullet_point('1. افتح الطلب واضغط على زر "إجراء"')
    pdf.bullet_point('2. اختر نوع الإجراء المطلوب')
    pdf.bullet_point('3. اكتب تفاصيل ما تم إنجازه')
    pdf.bullet_point('4. اختر الموظفين للإحالة (إن وجد)')
    pdf.bullet_point('5. غيّر الحالة إن لزم الأمر')
    pdf.bullet_point('6. اضغط "حفظ الإجراء"')
    
    pdf.section_title('سجل الإجراءات')
    pdf.body_text('يحتفظ النظام بسجل كامل لجميع الإجراءات على كل طلب يشمل:')
    pdf.bullet_point('اسم من قام بالإجراء')
    pdf.bullet_point('تاريخ ووقت الإجراء')
    pdf.bullet_point('تفاصيل الإجراء')
    pdf.bullet_point('الموظفين المحالين (إن وجد)')
    
    pdf.ln(3)
    pdf.section_title('صفحة مهامي المحالة')
    pdf.body_text('كل موظف يمكنه رؤية المهام المحالة إليه من صفحة "مهامي المحالة" والتي تعرض:')
    pdf.bullet_point('إحصائيات سريعة: إجمالي المهام، قيد الانتظار، قيد المعالجة، مكتملة')
    pdf.bullet_point('قائمة المهام مع تفاصيل كل مهمة')
    pdf.bullet_point('إمكانية تسجيل إجراء أو إحالة لموظف آخر')
    
    # === 6. الحضور والانصراف ===
    pdf.add_page()
    pdf.chapter_title('6. نظام الحضور والانصراف')
    
    pdf.body_text('نظام متكامل لتسجيل حضور وانصراف الموظفين مع تحديد الموقع الجغرافي.')
    
    pdf.section_title('تسجيل الحضور')
    pdf.bullet_point('1. افتح صفحة "الحضور والانصراف"')
    pdf.bullet_point('2. اسمح للمتصفح بالوصول للموقع')
    pdf.bullet_point('3. انتظر تحديد موقعك على الخريطة')
    pdf.bullet_point('4. اضغط زر "تسجيل الحضور"')
    
    pdf.section_title('تسجيل الانصراف')
    pdf.bullet_point('1. افتح صفحة "الحضور والانصراف"')
    pdf.bullet_point('2. أضف ملاحظات عن اليوم (اختياري)')
    pdf.bullet_point('3. اضغط زر "تسجيل الانصراف"')
    
    pdf.section_title('خريطة الموقع')
    pdf.body_text('تظهر الخريطة التفاعلية:')
    pdf.bullet_point('موقع المكتب (العلامة الذهبية)')
    pdf.bullet_point('موقعك الحالي (العلامة الخضراء)')
    pdf.bullet_point('يمكن النقر على "عرض على الخريطة" لأي سجل سابق')
    
    pdf.section_title('التنبيهات التلقائية')
    pdf.body_text('يظهر النظام تنبيهات تلقائية عند:')
    pdf.bullet_point('التأخر عن بداية الدوام')
    pdf.bullet_point('اقتراب نهاية الدوام')
    pdf.bullet_point('تجاوز وقت العمل المحدد')
    
    # === 7. التقارير ===
    pdf.add_page()
    pdf.chapter_title('7. التقارير')
    
    pdf.body_text('صفحة التقارير توفر تقارير شاملة عن أداء المكتب.')
    
    pdf.section_title('تقرير ملخص العمل')
    pdf.bullet_point('إجمالي المهام: المكتملة والمعلقة')
    pdf.bullet_point('إجمالي القضايا')
    pdf.bullet_point('إجمالي الاستشارات')
    
    pdf.section_title('تقرير الحضور')
    pdf.body_text('يعرض تقرير الحضور لفترة محددة:')
    pdf.bullet_point('إجمالي السجلات')
    pdf.bullet_point('أيام الحضور')
    pdf.bullet_point('إجمالي الساعات')
    pdf.bullet_point('تفاصيل كل موظف')
    
    pdf.section_title('تقرير الحضور الشهري')
    pdf.body_text('تقرير مفصل يُنشأ عند الطلب يشمل:')
    pdf.bullet_point('ملخص الشهر: السجلات، أيام الحضور، إجمالي الساعات')
    pdf.bullet_point('تفاصيل كل موظف: الأيام، الساعات، المتوسط، الحالة')
    pdf.bullet_point('تصنيف الحالة: طبيعي، ساعات إضافية، ساعات منخفضة')
    pdf.bullet_point('إمكانية الطباعة')
    
    # === 8. البريد الداخلي ===
    pdf.add_page()
    pdf.chapter_title('8. نظام البريد الداخلي')
    
    pdf.body_text('نظام مراسلات داخلي بين موظفي المكتب.')
    
    pdf.section_title('إرسال رسالة')
    pdf.bullet_point('1. اضغط "رسالة جديدة"')
    pdf.bullet_point('2. اختر المستلمين من القائمة')
    pdf.bullet_point('3. اكتب عنوان الرسالة')
    pdf.bullet_point('4. اكتب نص الرسالة')
    pdf.bullet_point('5. أرفق ملفات إن وجدت')
    pdf.bullet_point('6. اضغط "إرسال"')
    
    pdf.section_title('صناديق البريد')
    pdf.bullet_point('الوارد: الرسائل المستلمة')
    pdf.bullet_point('المرسل: الرسائل التي أرسلتها')
    pdf.bullet_point('المسودات: الرسائل غير المكتملة')
    
    pdf.section_title('الإشعارات')
    pdf.body_text('تظهر أيقونة الجرس في أعلى الصفحة عدد الإشعارات غير المقروءة. تشمل الإشعارات:')
    pdf.bullet_point('رسائل بريد جديدة')
    pdf.bullet_point('مهام محالة جديدة')
    pdf.bullet_point('تحديثات على الطلبات')
    
    # === 9. لوحة المسوق ===
    pdf.add_page()
    pdf.chapter_title('9. لوحة تحكم المسوق')
    
    pdf.body_text('لوحة تحكم خاصة بفريق التسويق لإدارة العملاء المحتملين والعروض.')
    
    pdf.section_title('إدارة العملاء المحتملين')
    pdf.body_text('لإضافة عميل محتمل جديد:')
    pdf.bullet_point('1. اضغط "إضافة عميل محتمل"')
    pdf.bullet_point('2. أدخل: الاسم، الجوال، البريد، الشركة')
    pdf.bullet_point('3. حدد مصدر العميل والخدمة المهتم بها')
    pdf.bullet_point('4. أضف ملاحظات إن وجدت')
    pdf.bullet_point('5. اضغط "حفظ"')
    
    pdf.section_title('حالات العميل المحتمل')
    pdf.bullet_point('جديد: تم إضافته حديثاً')
    pdf.bullet_point('تم التواصل: تم الاتصال به')
    pdf.bullet_point('مهتم: أبدى اهتماماً بالخدمات')
    pdf.bullet_point('تم إرسال عرض: تم إرسال عرض سعر')
    pdf.bullet_point('تحول لعميل: تم التعاقد معه')
    pdf.bullet_point('خسارة: لم يتم التعاقد')
    
    pdf.section_title('إنشاء عرض سعر')
    pdf.bullet_point('1. اضغط "إنشاء عرض" أو من صفحة العميل المحتمل')
    pdf.bullet_point('2. أدخل: العنوان، نوع الخدمة، التفاصيل')
    pdf.bullet_point('3. حدد المبلغ والخصم')
    pdf.bullet_point('4. اضغط "إنشاء العرض"')
    pdf.bullet_point('5. لإرسال العرض: اضغط "إرسال عبر واتساب"')
    
    pdf.section_title('التواصل عبر واتساب')
    pdf.bullet_point('واتساب الرسائل: لإرسال رسائل نصية')
    pdf.bullet_point('مكالمة صوتية: للاتصال الصوتي')
    pdf.bullet_point('يتم تسجيل جميع التواصلات في سجل التواصل')
    
    # === 10. بوابة العميل ===
    pdf.add_page()
    pdf.chapter_title('10. بوابة العميل')
    
    pdf.body_text('بوابة خاصة للعملاء لمتابعة طلباتهم وقضاياهم.')
    
    pdf.section_title('تقديم طلب جديد')
    pdf.body_text('يمكن للعميل تقديم طلب جديد من خلال:')
    pdf.bullet_point('طلب قضية: لتقديم قضية قانونية')
    pdf.bullet_point('طلب استشارة: للحصول على استشارة قانونية')
    pdf.bullet_point('طلب خدمة موثق: لخدمات التوثيق')
    
    pdf.section_title('متابعة الطلبات')
    pdf.body_text('يمكن للعميل متابعة حالة طلباته:')
    pdf.bullet_point('رقم الطلب وتاريخ التقديم')
    pdf.bullet_point('حالة الطلب الحالية')
    pdf.bullet_point('سجل الإجراءات المتخذة')
    pdf.bullet_point('الموظف المسؤول')
    
    pdf.section_title('التواصل مع المكتب')
    pdf.body_text('يظهر زر واتساب عائم في أسفل الصفحة للتواصل المباشر مع المكتب.')
    
    # === 11. واتساب ===
    pdf.add_page()
    pdf.chapter_title('11. التواصل عبر واتساب')
    
    pdf.body_text('النظام مدمج مع واتساب للتواصل السريع مع العملاء.')
    
    pdf.section_title('رقم المكتب الموحد')
    pdf.set_font('Arabic', 'B', 14)
    pdf.set_text_color(37, 211, 102)
    pdf.cell(0, 10, '+966 56 822 8974', new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
    pdf.set_text_color(0, 0, 0)
    
    pdf.section_title('أماكن تواجد زر واتساب')
    pdf.bullet_point('صفحة طلبات العملاء: بجانب كل طلب')
    pdf.bullet_point('صفحة العملاء: بجانب كل عميل')
    pdf.bullet_point('بوابة العميل: زر عائم ثابت')
    pdf.bullet_point('صفحة المهام المحالة: للتواصل مع العميل')
    pdf.bullet_point('لوحة المسوق: للتواصل مع العملاء المحتملين')
    
    pdf.section_title('إشعار العميل التلقائي')
    pdf.body_text('عند تحديث حالة طلب أو إضافة إجراء، يُسأل المستخدم:')
    pdf.bullet_point('"هل تريد إشعار العميل عبر واتساب؟"')
    pdf.bullet_point('عند الموافقة، يُفتح واتساب برسالة جاهزة تتضمن تفاصيل التحديث')
    
    # === 12. الدعم الفني ===
    pdf.add_page()
    pdf.chapter_title('12. الدعم الفني')
    
    pdf.section_title('للمساعدة والدعم')
    pdf.body_text('في حالة وجود أي مشكلة أو استفسار، يرجى التواصل مع:')
    pdf.ln(5)
    
    pdf.set_font('Arabic', '', 12)
    pdf.cell(0, 8, 'مكتب المحامي هشام يوسف الخياط', new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
    pdf.cell(0, 8, 'هاتف: +966 56 822 8974', new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
    pdf.cell(0, 8, 'البريد: hesham@hklaw.sa', new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
    
    pdf.ln(10)
    pdf.section_title('نصائح عامة')
    pdf.bullet_point('احرص على تغيير كلمة المرور بشكل دوري')
    pdf.bullet_point('لا تشارك بيانات الدخول مع أي شخص')
    pdf.bullet_point('تأكد من تسجيل الخروج عند الانتهاء')
    pdf.bullet_point('استخدم متصفح حديث للحصول على أفضل تجربة')
    
    pdf.ln(10)
    pdf.info_box('شكراً لاستخدامك النظام', 'نسعى دائماً لتطوير النظام وتحسين تجربة المستخدم. لا تتردد في إرسال ملاحظاتك واقتراحاتك.')
    
    # === حفظ الملف ===
    output_path = '/app/frontend/public/user_manual.pdf'
    pdf.output(output_path)
    print(f'✅ تم إنشاء الكتيب: {output_path}')
    return output_path

if __name__ == '__main__':
    create_manual()
