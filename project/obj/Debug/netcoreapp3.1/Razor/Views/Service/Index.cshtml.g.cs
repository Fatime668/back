#pragma checksum "C:\Users\user\source\repos\project\project\Views\Service\Index.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "4fb008468e1d6faf99d77fb135a9ba61955a89c3"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Service_Index), @"mvc.1.0.view", @"/Views/Service/Index.cshtml")]
namespace AspNetCore
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
#nullable restore
#line 1 "C:\Users\user\source\repos\project\project\Views\_ViewImports.cshtml"
using project.ViewModels;

#line default
#line hidden
#nullable disable
#nullable restore
#line 2 "C:\Users\user\source\repos\project\project\Views\_ViewImports.cshtml"
using project.Models;

#line default
#line hidden
#nullable disable
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"4fb008468e1d6faf99d77fb135a9ba61955a89c3", @"/Views/Service/Index.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"5fcded930a32da9b72a26bc2560ba7528a8701cd", @"/Views/_ViewImports.cshtml")]
    public class Views_Service_Index : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<HomeVM>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            WriteLiteral(@"<main>
    <section id=""breadcrumbs"">
        <div class=""container"">
            <ul class=""d-flex m-0 p-0"">
                <li class=""me-2""><a href=""#"">Home</a></li>/
                <li class=""ms-2""><a class=""active"" href=""#"">Services</a></li>
            </ul>
            <h2>Services</h2>
        </div>
    </section>
    <!-- Main End -->
    <!-- Services Start -->
    <section id=""cart"">
        <div class=""container"">
            <div class=""cart"">
                <div class=""row"">
                  ");
#nullable restore
#line 18 "C:\Users\user\source\repos\project\project\Views\Service\Index.cshtml"
             Write(await Html.PartialAsync("_CartPartialView", Model.Carts.Take(6)));

#line default
#line hidden
#nullable disable
            WriteLiteral(@"

                </div>
            </div>
        </div>
    </section>
    <!-- Services End -->
    <!-- Skils Start -->
    <section id=""skill"">
        <div class=""container"">
            <div class=""title"">
                <h2>Our Skills</h2>
                <p>
                    Magnam dolores commodi suscipit. Necessitatibus eius consequatur ex aliquid fuga eum quidem. Sit
                    sint
                    consectetur velit. Quisquam quos quisquam cupiditate. Et nemo qui impedit suscipit alias ea.
                    Quia
                    fugiat sit in iste officiis commodi quidem hic quas.
                </p>
            </div>
            <div class=""row"">
                <div class=""col-lg-6"">
                    <div class=""image"">
                        <img src=""https://bootstrapmade.com/demo/templates/Eterna/assets/img/skills-img.jpg""");
            BeginWriteAttribute("alt", " alt=\"", 1514, "\"", 1520, 0);
            EndWriteAttribute();
            WriteLiteral(@">
                    </div>
                </div>
                <div class=""col-lg-6"">
                    <div class=""content"">
                        <h2>Voluptatem dignissimos provident quasi corporis voluptates</h2>
                        <p>
                            Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor
                            incididunt
                            direna past reda
                        </p>

                    </div>
                    <div class=""values d-flex justify-content-between"">
                        <span>HTML</span>
                        <span>100%</span>
                    </div>
                    <div class=""progress"">

                        <div class=""progress-bar bg-danger"" role=""progressbar"" style=""width: 100%""
                             aria-valuenow=""100"" aria-valuemin=""100"" aria-valuemax=""100""></div>
                    </div>
                    <div class=""values d-flex justif");
            WriteLiteral(@"y-content-between"">
                        <span>CSS</span>
                        <span>90%</span>
                    </div>
                    <div class=""progress"">
                        <div class=""progress-bar bg-danger"" role=""progressbar"" style=""width: 90%"" aria-valuenow=""90""
                             aria-valuemin=""0"" aria-valuemax=""90""></div>
                    </div>
                    <div class=""values d-flex justify-content-between"">
                        <span>JAVASCRIPT</span>
                        <span>75%</span>
                    </div>
                    <div class=""progress"">
                        <div class=""progress-bar bg-danger"" role=""progressbar"" style=""width: 75%"" aria-valuenow=""75""
                             aria-valuemin=""75"" aria-valuemax=""75""></div>
                    </div>
                    <div class=""values d-flex justify-content-between"">
                        <span>PHOTOSHOP</span>
                        <span>55%</span>
       ");
            WriteLiteral(@"             </div>
                    <div class=""progress"">
                        <div class=""progress-bar bg-danger"" role=""progressbar"" style=""width: 55%"" aria-valuenow=""55""
                             aria-valuemin=""55"" aria-valuemax=""55""></div>
                    </div>
                </div>
            </div>
        </div>
    </section>
</main>");
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<HomeVM> Html { get; private set; }
    }
}
#pragma warning restore 1591
